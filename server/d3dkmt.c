/*
 * Server-side D3DKMT resource management
 *
 * Copyright 2025 Rémi Bernon for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"

#include "file.h"
#include "handle.h"
#include "request.h"
#include "security.h"

struct d3dkmt_object
{
    struct object       obj;            /* object header */
    enum d3dkmt_type    type;           /* object type */
    d3dkmt_handle_t     global;         /* object global handle */
    void               *runtime;        /* client runtime data */
    data_size_t         runtime_size;   /* size of client runtime data */
    struct fd          *fd;             /* fd object for unix fds */
};

static void d3dkmt_object_dump( struct object *obj, int verbose );
static struct fd *d3dkmt_object_get_fd( struct object *obj );
static void d3dkmt_object_destroy( struct object *obj );

static const struct object_ops d3dkmt_object_ops =
{
    sizeof(struct d3dkmt_object),   /* size */
    &no_type,                       /* type */
    d3dkmt_object_dump,             /* dump */
    no_add_queue,                   /* add_queue */
    NULL,                           /* remove_queue */
    NULL,                           /* signaled */
    NULL,                           /* satisfied */
    no_signal,                      /* signal */
    d3dkmt_object_get_fd,           /* get_fd */
    default_get_sync,               /* get_sync */
    default_map_access,             /* map_access */
    default_get_sd,                 /* get_sd */
    default_set_sd,                 /* set_sd */
    no_get_full_name,               /* get_full_name */
    no_lookup_name,                 /* lookup_name */
    no_link_name,                   /* link_name */
    NULL,                           /* unlink_name */
    no_open_file,                   /* open_file */
    no_kernel_obj_list,             /* get_kernel_obj_list */
    no_close_handle,                /* close_handle */
    d3dkmt_object_destroy,          /* destroy */
};

static enum server_fd_type d3dkmt_get_fd_type( struct fd *fd )
{
    return FD_TYPE_INVALID;
}

static const struct fd_ops d3dkmt_fd_ops =
{
    default_fd_get_poll_events,   /* get_poll_events */
    default_poll_event,           /* poll_event */
    d3dkmt_get_fd_type,           /* get_fd_type */
    no_fd_read,                   /* read */
    no_fd_write,                  /* write */
    no_fd_flush,                  /* flush */
    no_fd_get_file_info,          /* get_file_info */
    no_fd_get_volume_info,        /* get_volume_info */
    no_fd_ioctl,                  /* ioctl */
    default_fd_cancel_async,      /* cancel_async */
    no_fd_queue_async,            /* queue_async */
    default_fd_reselect_async     /* reselect_async */
};

struct keyed_wait
{
    struct list     entry;
    int             key;
    int             waiters;
    struct object  *sync;
};

struct d3dkmt_mutex
{
    struct d3dkmt_object base;
    unsigned int         key_value;      /* last released key value */
    unsigned __int64     fence_value;    /* last released fence value */
    bool                 abandoned;      /* mutex has been abandonned */
    struct thread       *owner;          /* current owner thread */
    struct list          waits;          /* list of pending keyed_waits */
    struct list          entry;          /* entry in owner d3dkmt_mutexes */
};

static void d3dkmt_mutex_dump( struct object *obj, int verbose );
static void d3dkmt_mutex_destroy( struct object *obj );

static const struct object_ops d3dkmt_mutex_ops =
{
    sizeof(struct d3dkmt_mutex),    /* size */
    &no_type,                       /* type */
    d3dkmt_mutex_dump,              /* dump */
    no_add_queue,                   /* add_queue */
    NULL,                           /* remove_queue */
    NULL,                           /* signaled */
    NULL,                           /* satisfied */
    no_signal,                      /* signal */
    no_get_fd,                      /* get_fd */
    default_get_sync,               /* get_sync */
    default_map_access,             /* map_access */
    default_get_sd,                 /* get_sd */
    default_set_sd,                 /* set_sd */
    no_get_full_name,               /* get_full_name */
    no_lookup_name,                 /* lookup_name */
    no_link_name,                   /* link_name */
    NULL,                           /* unlink_name */
    no_open_file,                   /* open_file */
    no_kernel_obj_list,             /* get_kernel_obj_list */
    no_close_handle,                /* close_handle */
    d3dkmt_mutex_destroy,           /* destroy */
};

#define DXGK_SHARED_SYNC_QUERY_STATE  0x0001
#define DXGK_SHARED_SYNC_MODIFY_STATE 0x0002
#define DXGK_SHARED_SYNC_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

static const WCHAR dxgk_shared_sync_name[] = {'D','x','g','k','S','h','a','r','e','d','S','y','n','c','O','b','j','e','c','t'};

struct type_descr dxgk_shared_sync_type =
{
    { dxgk_shared_sync_name, sizeof(dxgk_shared_sync_name) },           /* name */
    DXGK_SHARED_SYNC_ALL_ACCESS,                                        /* valid_access */
    {                                                                   /* mapping */
        STANDARD_RIGHTS_READ | DXGK_SHARED_SYNC_QUERY_STATE,
        STANDARD_RIGHTS_WRITE | DXGK_SHARED_SYNC_MODIFY_STATE,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
        DXGK_SHARED_SYNC_ALL_ACCESS,
    },
};

struct dxgk_shared_sync
{
    struct object   obj;    /* object header */
    struct object  *sync;   /* shared sync object */
};

static void dxgk_shared_sync_dump( struct object *obj, int verbose );
static void dxgk_shared_sync_destroy( struct object *obj );

static const struct object_ops dxgk_shared_sync_ops =
{
    sizeof(struct dxgk_shared_sync),    /* size */
    &dxgk_shared_sync_type,             /* type */
    dxgk_shared_sync_dump,              /* dump */
    no_add_queue,                       /* add_queue */
    NULL,                               /* remove_queue */
    NULL,                               /* signaled */
    NULL,                               /* satisfied */
    no_signal,                          /* signal */
    no_get_fd,                          /* get_fd */
    default_get_sync,                   /* get_sync */
    default_map_access,                 /* map_access */
    default_get_sd,                     /* get_sd */
    default_set_sd,                     /* set_sd */
    default_get_full_name,              /* get_full_name */
    no_lookup_name,                     /* lookup_name */
    directory_link_name,                /* link_name */
    default_unlink_name,                /* unlink_name */
    no_open_file,                       /* open_file */
    no_kernel_obj_list,                 /* get_kernel_obj_list */
    no_close_handle,                    /* close_handle */
    dxgk_shared_sync_destroy,           /* destroy */
};

static void dxgk_shared_sync_dump( struct object *obj, int verbose )
{
    struct dxgk_shared_sync *shared = (struct dxgk_shared_sync *)obj;
    assert( obj->ops == &dxgk_shared_sync_ops );
    fprintf( stderr, "DxgkSync sync=%p\n", shared->sync );
}

static void dxgk_shared_sync_destroy( struct object *obj )
{
    struct dxgk_shared_sync *shared = (struct dxgk_shared_sync *)obj;
    assert( obj->ops == &dxgk_shared_sync_ops );
    release_object( shared->sync );
}

#define DXGK_SHARED_RESOURCE_MODIFY_STATE 0x0001
#define DXGK_SHARED_RESOURCE_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x1)

static const WCHAR dxgk_shared_resource_name[] = {'D','x','g','k','S','h','a','r','e','d','R','e','s','o','u','r','c','e'};

struct type_descr dxgk_shared_resource_type =
{
    { dxgk_shared_resource_name, sizeof(dxgk_shared_resource_name) },   /* name */
    DXGK_SHARED_RESOURCE_ALL_ACCESS,                                    /* valid_access */
    {                                                                   /* mapping */
        STANDARD_RIGHTS_READ,
        STANDARD_RIGHTS_WRITE | DXGK_SHARED_RESOURCE_MODIFY_STATE,
        STANDARD_RIGHTS_EXECUTE,
        STANDARD_RIGHTS_REQUIRED | DXGK_SHARED_RESOURCE_MODIFY_STATE,
    },
};

struct dxgk_shared_resource
{
    struct object   obj;        /* object header */
    struct object  *resource;   /* shared resource object */
    struct object  *mutex;      /* shared keyed mutex object */
    struct object  *sync;       /* shared sync object */
};

static void dxgk_shared_resource_dump( struct object *obj, int verbose );
static void dxgk_shared_resource_destroy( struct object *obj );

static const struct object_ops dxgk_shared_resource_ops =
{
    sizeof(struct dxgk_shared_resource),    /* size */
    &dxgk_shared_resource_type,             /* type */
    dxgk_shared_resource_dump,              /* dump */
    no_add_queue,                           /* add_queue */
    NULL,                                   /* remove_queue */
    NULL,                                   /* signaled */
    NULL,                                   /* satisfied */
    no_signal,                              /* signal */
    no_get_fd,                              /* get_fd */
    default_get_sync,                       /* get_sync */
    default_map_access,                     /* map_access */
    default_get_sd,                         /* get_sd */
    default_set_sd,                         /* set_sd */
    default_get_full_name,                  /* get_full_name */
    no_lookup_name,                         /* lookup_name */
    directory_link_name,                    /* link_name */
    default_unlink_name,                    /* unlink_name */
    no_open_file,                           /* open_file */
    no_kernel_obj_list,                     /* get_kernel_obj_list */
    no_close_handle,                        /* close_handle */
    dxgk_shared_resource_destroy,           /* destroy */
};

static void dxgk_shared_resource_dump( struct object *obj, int verbose )
{
    struct dxgk_shared_resource *shared = (struct dxgk_shared_resource *)obj;
    assert( obj->ops == &dxgk_shared_resource_ops );
    fprintf( stderr, "DxgkResource resource=%p mutex=%p sync=%p\n", shared->resource,
             shared->mutex, shared->sync );
}

static void dxgk_shared_resource_destroy( struct object *obj )
{
    struct dxgk_shared_resource *shared = (struct dxgk_shared_resource *)obj;
    assert( obj->ops == &dxgk_shared_resource_ops );
    release_object( shared->resource );
    if (shared->mutex) release_object( shared->mutex );
    if (shared->sync) release_object( shared->sync );
}

static struct d3dkmt_object **objects, **objects_end, **objects_next;

#define D3DKMT_HANDLE_BIT  0x40000000

static d3dkmt_handle_t index_to_handle( int index )
{
    return (index << 6) | D3DKMT_HANDLE_BIT | 2;
}

static int handle_to_index( d3dkmt_handle_t handle )
{
    return (handle & ~0xc000003f) >> 6;
}

static bool init_handle_table(void)
{
    static const size_t initial_capacity = 1024;

    if (!(objects = mem_alloc( initial_capacity * sizeof(*objects) ))) return false;
    memset( objects, 0, initial_capacity * sizeof(*objects) );
    objects_end = objects + initial_capacity;
    objects_next = objects;

    return true;
}

static struct d3dkmt_object **grow_handle_table(void)
{
    size_t old_capacity = objects_end - objects, max_capacity = handle_to_index( D3DKMT_HANDLE_BIT - 1 );
    unsigned int new_capacity = old_capacity * 3 / 2;
    struct d3dkmt_object **tmp;

    if (new_capacity > max_capacity) new_capacity = max_capacity;
    if (new_capacity <= old_capacity) return NULL; /* exhausted handle capacity */

    if (!(tmp = realloc( objects, new_capacity * sizeof(*objects) ))) return NULL;
    memset( tmp + old_capacity, 0, (new_capacity - old_capacity) * sizeof(*tmp) );

    objects = tmp;
    objects_end = tmp + new_capacity;
    objects_next = tmp + old_capacity;

    return objects_next;
}

/* allocate a d3dkmt object with a global handle */
static d3dkmt_handle_t alloc_object_handle( struct d3dkmt_object *object )
{
    struct d3dkmt_object **entry;
    d3dkmt_handle_t handle = 0;

    if (!objects && !init_handle_table()) goto done;

    for (entry = objects_next; entry < objects_end; entry++) if (!*entry) break;
    if (entry == objects_end)
    {
        for (entry = objects; entry < objects_next; entry++) if (!*entry) break;
        if (entry == objects_next && !(entry = grow_handle_table())) goto done;
    }

    handle = index_to_handle( entry - objects );
    objects_next = entry + 1;
    *entry = object;

done:
    if (!handle) set_error( STATUS_NO_MEMORY );
    return handle;
}

/* free a d3dkmt global object handle */
static void free_object_handle( d3dkmt_handle_t global )
{
    unsigned int index = handle_to_index( global );
    assert( objects + index < objects_end );
    objects[index] = NULL;
}

/* return a pointer to a d3dkmt object from its global handle */
static void *get_d3dkmt_object( d3dkmt_handle_t global, enum d3dkmt_type type )
{
    unsigned int index = handle_to_index( global );
    struct d3dkmt_object *object;

    if (objects + index >= objects_end) object = NULL;
    else object = objects[index];

    if (!object || object->global != global || object->type != type) return NULL;
    return object;
}

static void d3dkmt_object_dump( struct object *obj, int verbose )
{
    struct d3dkmt_object *object = (struct d3dkmt_object *)obj;
    assert( obj->ops == &d3dkmt_object_ops );

    fprintf( stderr, "type=%#x global=%#x\n", object->type, object->global );
}

static struct fd *d3dkmt_object_get_fd( struct object *obj )
{
    struct d3dkmt_object *object = (struct d3dkmt_object *)obj;
    assert( obj->ops == &d3dkmt_object_ops );

    if (object->fd) return (struct fd *)grab_object( object->fd );

    set_error( STATUS_NO_SUCH_FILE );
    return NULL;
}

static void d3dkmt_object_destroy( struct object *obj )
{
    struct d3dkmt_object *object = (struct d3dkmt_object *)obj;
    assert( obj->ops == &d3dkmt_object_ops );

    if (object->global) free_object_handle( object->global );
    if (object->fd) release_object( object->fd );
    free( object->runtime );
}

static struct d3dkmt_object *d3dkmt_object_create( enum d3dkmt_type type, data_size_t runtime_size, const void *runtime )
{
    struct d3dkmt_object *object;

    if (!(object = alloc_object( &d3dkmt_object_ops ))) return NULL;
    object->type            = type;
    object->global          = 0;
    object->runtime_size    = runtime_size;
    object->fd              = NULL;

    if (!(object->runtime = memdup( runtime, runtime_size )) ||
        !(object->global = alloc_object_handle( object )))
    {
        release_object( object );
        return NULL;
    }

    return object;
}

static void d3dkmt_mutex_dump( struct object *obj, int verbose )
{
    struct d3dkmt_mutex *mutex = (struct d3dkmt_mutex *)obj;
    assert( obj->ops == &d3dkmt_mutex_ops );

    fprintf( stderr, "d3dkmt mutex global=%#x\n", mutex->base.global );
}

static void d3dkmt_mutex_destroy( struct object *obj )
{
    struct d3dkmt_mutex *mutex = (struct d3dkmt_mutex *)obj;
    struct keyed_wait *wait, *next;

    assert( obj->ops == &d3dkmt_mutex_ops );

    LIST_FOR_EACH_ENTRY_SAFE( wait, next, &mutex->waits, struct keyed_wait, entry )
    {
        release_object( wait->sync );
        list_remove( &wait->entry );
        free( wait );
    }

    if (mutex->base.global) free_object_handle( mutex->base.global );
    free( mutex->base.runtime );
}

static struct d3dkmt_object *d3dkmt_mutex_create( unsigned int key_value, data_size_t runtime_size, const void *runtime )
{
    struct d3dkmt_mutex *object;

    if (!(object = alloc_object( &d3dkmt_mutex_ops ))) return NULL;
    object->base.type            = D3DKMT_MUTEX;
    object->base.global          = 0;
    object->base.runtime_size    = runtime_size;
    object->base.fd              = NULL;
    object->key_value            = key_value;
    object->fence_value          = 0;
    object->abandoned            = false;
    object->owner                = NULL;
    list_init( &object->waits );

    if (!(object->base.runtime = memdup( runtime, runtime_size )) ||
        !(object->base.global = alloc_object_handle( &object->base )))
    {
        release_object( object );
        return NULL;
    }

    return &object->base;
}

static struct object *keyed_wait_grab( struct d3dkmt_mutex *mutex, int key )
{
    struct keyed_wait *wait;

    LIST_FOR_EACH_ENTRY( wait, &mutex->waits, struct keyed_wait, entry )
    {
        if (wait->key != key) continue;
        wait->waiters++;
        return grab_object( wait->sync );
    }

    if (!(wait = mem_alloc( sizeof(*wait) ))) return NULL;
    wait->key       = key;
    wait->waiters   = 1;
    if (!(wait->sync = create_internal_sync( 0, 0 )))
    {
        free( wait );
        return NULL;
    }

    list_add_tail( &mutex->waits, &wait->entry );
    return grab_object( wait->sync );
}

static void keyed_wait_release( struct d3dkmt_mutex *mutex, int key )
{
    struct keyed_wait *wait;

    LIST_FOR_EACH_ENTRY( wait, &mutex->waits, struct keyed_wait, entry )
    {
        if (wait->key == key && !--wait->waiters)
        {
            release_object( wait->sync );
            list_remove( &wait->entry );
            free( wait );
            break;
        }
    }
}

static void mutex_grab( struct d3dkmt_mutex *mutex )
{
    grab_object( mutex );
    list_add_tail( &current->d3dkmt_mutexes, &mutex->entry );
    mutex->owner = current;
}

static void mutex_release( struct d3dkmt_mutex *mutex, bool abandon )
{
    struct keyed_wait *wait;

    LIST_FOR_EACH_ENTRY( wait, &mutex->waits, struct keyed_wait, entry )
    {
        if (abandon || wait->key == mutex->key_value)
        {
            signal_sync( wait->sync );
            if (!abandon) break;
        }
    }
    if (abandon) mutex->abandoned = true;

    mutex->owner = NULL;
    list_remove( &mutex->entry );
    release_object( mutex );
}

void abandon_d3dkmt_mutexes( struct thread *thread )
{
    struct d3dkmt_mutex *mutex, *next;

    LIST_FOR_EACH_ENTRY_SAFE( mutex, next, &thread->d3dkmt_mutexes, struct d3dkmt_mutex, entry )
        mutex_release( mutex, true );
}

/* return a pointer to a d3dkmt object from its global handle */
static void *d3dkmt_object_open( d3dkmt_handle_t global, enum d3dkmt_type type )
{
    struct d3dkmt_object *object;

    if (!(object = get_d3dkmt_object( global, type )))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return NULL;
    }
    return grab_object( object );
}

static struct d3dkmt_object *d3dkmt_object_open_shared( obj_handle_t handle, enum d3dkmt_type type )
{
    struct object *obj, *ret = NULL;

    if ((obj = get_handle_obj( current->process, handle, 0, &dxgk_shared_resource_ops )))
    {
        struct dxgk_shared_resource *shared = (struct dxgk_shared_resource *)obj;
        if (type == D3DKMT_RESOURCE) ret = grab_object( shared->resource );
        else if (type == D3DKMT_MUTEX && shared->mutex) ret = grab_object( shared->mutex );
        else if (type == D3DKMT_SYNC && shared->sync) ret = grab_object( shared->sync );
        release_object( obj );
        if (!ret) set_error( STATUS_INVALID_PARAMETER );
        return (struct d3dkmt_object *)ret;
    }

    if (type != D3DKMT_SYNC) return NULL;

    /* try again looking for a shared sync if client asked for a sync object */
    set_error( STATUS_SUCCESS );

    if ((obj = get_handle_obj( current->process, handle, 0, &dxgk_shared_sync_ops )))
    {
        struct dxgk_shared_sync *shared = (struct dxgk_shared_sync *)obj;
        ret = grab_object( shared->sync );
        release_object( obj );
    }

    return (struct d3dkmt_object *)ret;
}

/* create a global d3dkmt object */
DECL_HANDLER(d3dkmt_object_create)
{
    struct d3dkmt_object *object;
    struct fd *fd = NULL;

    if (req->fd >= 0)
    {
        int unix_fd;
        if ((unix_fd = thread_get_inflight_fd( current, req->fd )) < 0) return;
        if (!(fd = create_anonymous_fd( NULL, unix_fd, NULL, 0 ))) return;
    }

    switch (req->type)
    {
    case D3DKMT_MUTEX:
        if (!(object = d3dkmt_mutex_create( req->value, get_req_data_size(), get_req_data() ))) goto done;
        break;
    default:
        if (!(object = d3dkmt_object_create( req->type, get_req_data_size(), get_req_data() ))) goto done;
        break;
    }

    if (fd)
    {
        set_fd_user( fd, &d3dkmt_fd_ops, &object->obj );
        object->fd = (struct fd *)grab_object( fd );
    }

    reply->handle = alloc_handle( current->process, object, STANDARD_RIGHTS_ALL, OBJ_INHERIT );
    reply->global = object->global;
    release_object( object );

done:
    if (fd) release_object( fd );
}

/* update a global d3dkmt object */
DECL_HANDLER(d3dkmt_object_update)
{
    struct d3dkmt_object *object;
    void *tmp, *runtime;
    data_size_t size;

    if (!(size = get_req_data_size())) runtime = NULL;
    else if (!(runtime = memdup( get_req_data(), size ))) return;

    if (!(object = d3dkmt_object_open( req->global, req->type ))) goto done;
    tmp = object->runtime;
    object->runtime = runtime;
    object->runtime_size = size;
    runtime = tmp;
    release_object( object );

done:
    free( runtime );
}

/* query a global d3dkmt object */
DECL_HANDLER(d3dkmt_object_query)
{
    struct d3dkmt_object *object;

    if (req->global) object = d3dkmt_object_open( req->global, req->type );
    else object = d3dkmt_object_open_shared( req->handle, req->type );
    if (!object) return;

    reply->runtime_size = object->runtime_size;
    release_object( object );
}

/* open a global d3dkmt object */
DECL_HANDLER(d3dkmt_object_open)
{
    data_size_t runtime_size = get_reply_max_size();
    struct d3dkmt_object *object;
    obj_handle_t handle;

    if (req->global) object = d3dkmt_object_open( req->global, req->type );
    else object = d3dkmt_object_open_shared( req->handle, req->type );
    if (!object) return;

    /* only resource objects require exact runtime buffer size match */
    if (object->type != D3DKMT_RESOURCE && runtime_size > object->runtime_size) runtime_size = object->runtime_size;

    if (runtime_size && object->runtime_size != runtime_size) set_error( STATUS_INVALID_PARAMETER );
    else if ((handle = alloc_handle( current->process, object, STANDARD_RIGHTS_ALL, OBJ_INHERIT )))
    {
        reply->handle = handle;
        reply->global = object->global;
        reply->runtime_size = object->runtime_size;
        if (runtime_size) set_reply_data( object->runtime, object->runtime_size );
    }

    release_object( object );
}

/* share global d3dkmt objects together */
DECL_HANDLER(d3dkmt_share_objects)
{
    struct object *resource = NULL, *mutex = NULL, *sync = NULL;
    const struct object_attributes *objattr;
    const struct security_descriptor *sd;
    struct unicode_str name;
    struct object *root;

    if (!(objattr = get_req_object_attributes( &sd, &name, &root ))) return;

    if (req->resource)
    {
        struct dxgk_shared_resource *shared;

        if (!(resource = d3dkmt_object_open( req->resource, D3DKMT_RESOURCE ))) return;
        if (req->mutex && !(mutex = d3dkmt_object_open( req->mutex, D3DKMT_MUTEX ))) goto done;
        if (req->sync && !(sync = d3dkmt_object_open( req->sync, D3DKMT_SYNC ))) goto done;

        if (!(shared = create_named_object( root, &dxgk_shared_resource_ops, &name, objattr->attributes | OBJ_CASE_INSENSITIVE, NULL ))) goto done;
        shared->resource = grab_object( resource );
        if ((shared->mutex = mutex)) grab_object( mutex );
        if ((shared->sync = sync)) grab_object( sync );
        reply->handle = alloc_handle( current->process, shared, req->access, OBJ_INHERIT );
        release_object( shared );
    }
    else
    {
        struct dxgk_shared_sync *shared;

        if (!(sync = d3dkmt_object_open( req->sync, D3DKMT_SYNC ))) return;

        if (!(shared = create_named_object( root, &dxgk_shared_sync_ops, &name, objattr->attributes | OBJ_CASE_INSENSITIVE, NULL ))) goto done;
        shared->sync = grab_object( sync );
        reply->handle = alloc_handle( current->process, shared, req->access, OBJ_INHERIT );
        release_object( shared );
    }

done:
    if (resource) release_object( resource );
    if (mutex) release_object( mutex );
    if (sync) release_object( sync );
}

/* open a shared d3dkmt object from its name */
DECL_HANDLER(d3dkmt_object_open_name)
{
    struct unicode_str name = get_req_unicode_str();

    switch (req->type)
    {
    case D3DKMT_SYNC:
        reply->handle = open_object( current->process, req->rootdir, req->access, &dxgk_shared_sync_ops,
                                     &name, req->attributes | OBJ_CASE_INSENSITIVE );
        break;
    case D3DKMT_RESOURCE:
        reply->handle = open_object( current->process, req->rootdir, req->access, &dxgk_shared_resource_ops,
                                     &name, req->attributes | OBJ_CASE_INSENSITIVE );
        break;
    default:
        set_error( STATUS_INVALID_PARAMETER );
        break;
    }
}

/* Acquire a global d3dkmt keyed mutex */
DECL_HANDLER(d3dkmt_mutex_acquire)
{
    struct d3dkmt_mutex *mutex;
    struct object *sync;

    if (!(mutex = d3dkmt_object_open( req->mutex, D3DKMT_MUTEX ))) goto done;

    if (req->wait_status) set_error( req->wait_status );
    else if (mutex->abandoned) set_error( STATUS_ABANDONED );
    else if (mutex->key_value == req->key_value && !mutex->owner)
    {
        reply->fence_value = mutex->fence_value;
        mutex_grab( mutex );
    }
    else if ((reply->wait_handle = req->wait_handle)) set_error( STATUS_PENDING );
    else if ((sync = keyed_wait_grab( mutex, req->key_value )))
    {
        if ((reply->wait_handle = alloc_handle( current->process, sync, SYNCHRONIZE, 0 ))) set_error( STATUS_PENDING );
        release_object( sync );
    }

    release_object( mutex );

done:
    if (get_error() != STATUS_PENDING && req->wait_handle)
    {
        close_handle( current->process, req->wait_handle );
        if (mutex) keyed_wait_release( mutex, req->key_value );
    }
}

/* Release a global d3dkmt keyed mutex */
DECL_HANDLER(d3dkmt_mutex_release)
{
    struct d3dkmt_mutex *mutex;

    if (!(mutex = d3dkmt_object_open( req->mutex, D3DKMT_MUTEX ))) return;

    if (mutex->abandoned) set_error( STATUS_ABANDONED );
    else if (mutex->owner != current) set_error( STATUS_INVALID_PARAMETER );
    else
    {
        mutex->key_value = req->key_value;
        mutex->fence_value = req->fence_value;
        mutex_release( mutex, req->abandon );
    }

    release_object( mutex );
}
