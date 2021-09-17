#include <stdio.h>
#include <anjay/anjay.h>
#include <anjay/security.h>
#include <anjay/attr_storage.h>
#include <anjay/server.h>
#include <poll.h>

int mainLoop(anjay_t *anjay)
{
    while (true)
    {
        AVS_LIST(avs_net_socket_t *const) sockets = anjay_get_sockets(anjay);

        size_t numsocks = AVS_LIST_SIZE(sockets);
        struct pollfd pollfds[numsocks];
        size_t i = 0;
        AVS_LIST(avs_net_socket_t *const) sock;
        AVS_LIST_FOREACH(sock, sockets)
        {
            pollfds[i].fd       = *(const int *) avs_net_socket_get_system(*sock);
            pollfds[i].events   = POLLIN;
            pollfds[i].revents  = 0;
            ++i;
        }

        const int maxWaitTimeMs = 1000;
        int waitMs = anjay_sched_calculate_wait_time_ms(anjay, maxWaitTimeMs);

        if (poll(pollfds, numsocks, waitMs) > 0)
        {
            int socketId = 0;
            AVS_LIST(avs_net_socket_t *const) socket = NULL;
            AVS_LIST_FOREACH(socket, sockets)
            {
                if (pollfds[socketId].revents) {
                    if (anjay_serve(anjay, *socket)) {
                        printf("anjay_serve failed\n");
                    }
                }
                ++socketId;
            }
        }

        anjay_sched_run(anjay);
    }

    return 0;
}

static int setupSecurityObject(anjay_t *anjay)
{
    if (anjay_security_object_install(anjay))
    {
        return -1;
    }

    const anjay_security_instance_t securityInstance = {
            .ssid           = 1,
            .server_uri     = "coap://localhost:5683",
            .security_mode  = ANJAY_SECURITY_NOSEC
    };

    anjay_iid_t securityInstanceId = ANJAY_ID_INVALID;
    if (anjay_security_object_add_instance(anjay, &securityInstance, &securityInstanceId))
    {
        return -1;
    }

    return 0;
}

static int setupServerObject(anjay_t *anjay)
{
    if (anjay_server_object_install(anjay))
    {
        return -1;
    }

    const anjay_server_instance_t serverInstance = {
            .ssid               = 1,
            .lifetime           = 60,
            .default_min_period = -1,
            .default_max_period = -1,
            .disable_timeout    = -1,
            .binding            = "U"
    };

    anjay_iid_t serverInstanceId = ANJAY_ID_INVALID;
    if (anjay_server_object_add_instance(anjay, &serverInstance, &serverInstanceId))
    {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("No Endpoint Name\n");
        return -1;
    }

    const anjay_configuration_t CONFIG = {
            .endpoint_name      = argv[1],
            .in_buffer_size     = 4000,
            .out_buffer_size    = 4000,
            .msg_cache_size     = 4000
    };

    anjay_t *anjay = anjay_new(&CONFIG);
    if (!anjay)
    {
        printf("Could not create Anjay Object\n");
        return -1;
    }

    int result = 0;
    if (anjay_attr_storage_install(anjay) || setupSecurityObject(anjay) || setupServerObject(anjay))
    {
        result = -1;
    }

    if (!result)
    {
        result = mainLoop((anjay));
    }

    anjay_delete(anjay);
    return 0;
}
