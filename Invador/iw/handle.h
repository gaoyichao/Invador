#ifndef HANDLE_H
#define HANDLE_H

int handle_dev_dump(struct nl80211_state *state,
               struct nl_msg *msg,
               int argc, char **argv,
               enum id_input id);

#endif // HANDLE_H
