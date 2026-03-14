#ifndef UDPKG_TRIGGER_H
#define UDPKG_TRIGGER_H

#define TRIG_AWAIT   0
#define TRIG_NOAWAIT 1

void trig_set_admindir(const char *dir);

int  trig_parse_file(const char *path,
                     void (*icb)(const char *, int, void *), void *idata,
                     void (*acb)(const char *, int, void *), void *adata);

int  trig_install_interests(const char *pkg, const char *src);
int  trig_remove_interests(const char *pkg);

int  trig_pending_add(const char *trigname, const char *by_pkg, int noawait);
int  trig_pending_run(int (*run_postinst)(const char *, const char *));
void trig_pending_clear(void);

int  trig_activate_from_file(const char *triggers_file, const char *by_pkg,
                              int force_noawait);
int  trig_process_for_pkg(const char *pkg_triggers_file,
                           int (*run_postinst)(const char *, const char *));

int  op_trigger(const char *trigname, const char *by_pkg,
                int noawait, int no_act);
int  op_check_supported(void);

#endif
