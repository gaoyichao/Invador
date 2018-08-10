#include "ByNetEngine.h"

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int *ret = (int*)arg;
    *ret = err->error;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *ret = (int*)arg;
    *ret = 0;
    return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *ret = (int*)arg;
    *ret = 0;
    return NL_STOP;
}

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(ByNetHandlerPtr handler, void *data)
{
    registered_handler = handler;
    registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
    if (registered_handler)
        return registered_handler(msg, registered_handler_data);

    return NL_OK;
}

/**********************************************************************/


/**********************************************************************/

/*
 * BYNetEngine默认构造函数
 */
BYNetEngine::BYNetEngine()
{
    m_nlstate.nl_sock = nl_socket_alloc();
    if (!m_nlstate.nl_sock)
        throw "Failed to allocate netlink socket";

    if (genl_connect(m_nlstate.nl_sock)) {
        nl_socket_free(m_nlstate.nl_sock);
        throw "Failed to connect to generic netlink";
    }

    nl_socket_set_buffer_size(m_nlstate.nl_sock, 8192, 8192);

    m_nlstate.nl80211_id = genl_ctrl_resolve(m_nlstate.nl_sock, "nl80211");
    if (m_nlstate.nl80211_id < 0) {
        nl_socket_free(m_nlstate.nl_sock);
        throw "nl80211 not found";
    }
}
/*
 * BYNetEngine析构函数
 */
BYNetEngine::~BYNetEngine()
{
    nl_socket_free(m_nlstate.nl_sock);
}

#include <iostream>
int BYNetEngine::handle_cmd(int nlm, enum nl80211_commands cmd, ByNetHandler handler, void *arg)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);

    genlmsg_put(msg, 0, 0, m_nlstate.nl80211_id, 0, nlm, cmd, 0);

    int err = handler(this, msg, arg);
    if (err)
        goto out;

    err = nl_send_auto_complete(m_nlstate.nl_sock, msg);
    if (err < 0)
        goto out;

    err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

    while (err > 0)
        nl_recvmsgs(m_nlstate.nl_sock, cb);

out:
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}
