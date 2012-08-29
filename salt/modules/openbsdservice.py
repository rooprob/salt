'''
The service module for OpenBSD
'''
# Import Python libs
import os
# Import Salt libs


# XXX enable/disable support would be nice


def __virtual__():
    '''
    Only work on OpenBSD
    '''
    if __grains__['os'] == 'OpenBSD' and os.path.exists('/etc/rc.d/rc.subr'):
        v = map(int, __grains__['kernelrelease'].split('.'))
        # The -f flag, used to force a script to run even if disabled,
        # was added after the 5.0 release.
        if v[0] > 5 or (v[0] == 5 and v[1] > 0):
            return 'service'
    return False


def start(name):
    '''
    Start the specified service

    CLI Example::

        salt '*' service.start <service name>
    '''
    cmd = '/etc/rc.d/{0} -f start'.format(name)
    return not __salt__['cmd.retcode'](cmd)


def stop(name):
    '''
    Stop the specified service

    CLI Example::

        salt '*' service.stop <service name>
    '''
    cmd = '/etc/rc.d/{0} -f stop'.format(name)
    return not __salt__['cmd.retcode'](cmd)


def restart(name):
    '''
    Restart the named service

    CLI Example::

        salt '*' service.restart <service name>
    '''
    if name == 'salt-minion':
        salt.utils.daemonize_if(__opts__)
    cmd = '/etc/rc.d/{0} -f restart'.format(name)
    return not __salt__['cmd.retcode'](cmd)


def status(name):
    '''
    Return the status for a service, returns a bool whether the service is
    running.

    CLI Example::

        salt '*' service.status <service name>
    '''
    cmd = '/etc/rc.d/{0} -f check'.format(name)
    return not __salt__['cmd.retcode'](cmd)
