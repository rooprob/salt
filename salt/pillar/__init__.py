'''
Render the pillar data
'''

# Import python libs
import os
import re
import copy
import collections
import logging
import subprocess

# Import Salt libs
import salt.loader
import salt.fileclient
import salt.minion
import salt.crypt
from salt._compat import string_types
from salt.template import compile_template

# Import third party libs
import zmq
import yaml

log = logging.getLogger(__name__)


def get_pillar(opts, grains, id_, env=None):
    '''
    Return the correct pillar driver based on the file_client option
    '''
    try:
        log.info("SSS get_pillar: with opts:".format(opts['file_client']))
        return {
                'remote': RemotePillar,
                'local': Pillar
               }.get(opts['file_client'], 'local')(opts, grains, id_, env)
    except KeyError:
        return Pillar(opts, grains, id_, env)

def _merge(dst, src):
    '''
    Perform an datastructure merge of pillar as new pillar data is found.
    New data overwrites old data.

    XXX Improve by signalling to client when datastructures are incompatible.
    Right now the new data structure quietly wins. Checking structure is left
    to the pillar template code.
    '''
    stack = [(dst, src)]
    log.debug("XXX <<<<<< {0}".format(src))
    log.debug("XXX ====== {0}".format(dst))
    while stack:
        current_dst, current_src = stack.pop()
        for key in current_src:
            if key not in current_dst:
                log.debug("XXX merging direct {0}".format(key))
                current_dst[key] = current_src[key]
            else:
                if isinstance(current_src[key], dict) and isinstance(current_dst[key], dict) :
                    log.debug("XXX merging HASH {0} {1} >>> {2}".format(key, current_src[key], current_dst[key]))
                    stack.append((current_dst[key], current_src[key]))
                elif isinstance(current_src[key], list) and isinstance(current_dst[key], list) :
                    log.debug("XXX merging LIST {0} {1} >>> {2}".format(key, current_src[key], current_dst[key]))
                    current_dst[key] = list(set(current_dst[key] + current_src[key]))
                else:
                    log.debug("XXX merging SCALAR {0} {1} >>> {2}".format(key,
                        current_src[key], current_dst[key]))
                    current_dst[key] = current_src[key]

    log.debug("XXX >>>>>>> {0}".format(dst))
    return dst

class RemotePillar(object):
    '''
    Get the pillar from the master
    '''
    def __init__(self, opts, grains, id_, env):
        self.opts = opts
        self.opts['environment'] = env
        self.grains = grains
        self.id_ = id_
        self.serial = salt.payload.Serial(self.opts)
        self.sreq = salt.payload.SREQ(self.opts['master_uri'])
        self.auth = salt.crypt.SAuth(opts)

    def compile_pillar(self):
        '''
        Return the pillar data from the master
        '''
        load = {'id': self.id_,
                'grains': self.grains,
                'env': self.opts['environment'],
                'cmd': '_pillar'}
        return self.auth.crypticle.loads(
                self.sreq.send('aes', self.auth.crypticle.dumps(load), 3, 7200)
                )



class Pillar(object):
    '''
    Read over the pillar top files and render the pillar data
    '''

    def __init__(self, opts, grains, id_, env):
        # use the local file client
        self.opts = self.__gen_opts(opts, grains, id_, env)
        self.client = salt.fileclient.get_file_client(self.opts)
        self.matcher = salt.minion.Matcher(self.opts)
        self.functions = salt.loader.minion_mods(self.opts)
        self.rend = salt.loader.render(self.opts, self.functions)
        self.ext_pillars = salt.loader.pillars(self.opts, self.functions)
        self.pillar_hieradb()
        log.info("XXX pillar_hieradb {0}".format(self.pillar_hieradb))

    def __gen_opts(self, opts, grains, id_, env=None):
        '''
        The options need to be altered to conform to the file client
        '''
        opts = copy.deepcopy(opts)
        opts['file_roots'] = opts['pillar_roots']
        opts['file_client'] = 'local'
        opts['grains'] = grains
        opts['pillar'] = {}
        opts['id'] = id_
        if 'environment' not in opts:
            opts['environment'] = env
        if opts['state_top'].startswith('salt://'):
            opts['state_top'] = opts['state_top']
        elif opts['state_top'].startswith('/'):
            opts['state_top'] = os.path.join('salt://', opts['state_top'][1:])
        else:
            opts['state_top'] = os.path.join('salt://', opts['state_top'])
        return opts

    def _get_envs(self):
        '''
        Pull the file server environments out of the master options
        '''
        envs = set(['base'])
        if 'file_roots' in self.opts:
            envs.update(list(self.opts['file_roots']))
        return envs

    def get_tops(self):
        '''
        Gather the top files
        '''
        tops = collections.defaultdict(list)
        include = collections.defaultdict(list)
        done = collections.defaultdict(list)
        errors = []
        # Gather initial top files
        try:
            if self.opts['environment']:
                tops[self.opts['environment']] = [
                        compile_template(
                            self.client.cache_file(
                                self.opts['state_top'],
                                self.opts['environment']
                                ),
                            self.rend,
                            self.opts['renderer'],
                            self.opts['environment']
                            )
                        ]
            else:
                for env in self._get_envs():
                    tops[env].append(
                            compile_template(
                                self.client.cache_file(
                                    self.opts['state_top'],
                                    env
                                    ),
                                self.rend,
                                self.opts['renderer'],
                                env=env
                                )
                            )
        except Exception as exc:
            errors.append(
                    ('Rendering Primary Top file failed, render error:\n{0}'
                        .format(exc)))

        # Search initial top files for includes
        log.info("XXX get_opts... {0}".format(tops.items()))
        for env, ctops in tops.items():
            for ctop in ctops:
                if not 'include' in ctop:
                    continue
                for sls in ctop['include']:

                    log.info("XXX processing include {0}".format(sls))

                    include[env].append(sls)
                ctop.pop('include')
        # Go through the includes and pull out the extra tops and add them
        while include:
            pops = []
            for env, states in include.items():
                log.info("XXX looping {0} {1}".format(env, states))
                pops.append(env)
                if not states:
                    continue
                for sls in states:
                    if sls in done[env]:
                        continue
                    try:
                        tops[env].append(
                                compile_template(
                                    self.client.get_state(
                                        sls,
                                        env
                                        ),
                                    self.rend,
                                    self.opts['renderer'],
                                    env=env
                                    )
                                )
                    except Exception as exc:
                        errors.append(
                                ('Rendering Top file {0} failed, render error'
                                 ':\n{1}').format(sls, exc))
                    done[env].append(sls)
            for env in pops:
                if env in include:
                    include.pop(env)

        return tops, errors

    def merge_tops(self, tops):
        '''
        Cleanly merge the top files
        '''
        top = collections.defaultdict(dict)
        for sourceenv, ctops in tops.items():
            for ctop in ctops:
                for env, targets in ctop.items():
                    if env == 'include':
                        continue
                    for tgt in targets:
                        if not tgt in top[env]:
                            top[env][tgt] = ctop[env][tgt]
                            continue
                        matches = []
                        states = set()
                        for comp in top[env][tgt]:
                            if isinstance(comp, dict):
                                matches.append(comp)
                            if isinstance(comp, string_types):
                                states.add(comp)
                        top[env][tgt] = matches
                        top[env][tgt].extend(list(states))
        log.debug("XXX merged_tops into {0}".format(top))
        return top

    def get_top(self):
        '''
        Returns the high data derived from the top file
        '''
        tops, errors = self.get_tops()
        return self.merge_tops(tops), errors

    def top_matches(self, top):
        '''
        Search through the top high data for matches and return the states
        that this minion needs to execute.

        Returns:
        {'env': ['state1', 'state2', ...]}
        '''
        matches = {}
        for env, body in top.items():
            if self.opts['environment']:
                if not env == self.opts['environment']:
                    continue
            for match, data in body.items():
                if self.matcher.confirm_top(
                        match,
                        data,
                        self.opts.get('nodegroups', {}),
                        ):
                    if env not in matches:
                        matches[env] = []
                    for item in data:
                        if isinstance(item, string_types):
                            matches[env].append(item)
        return matches

    def render_pstate(self, sls, env, mods):
        '''
        Collect a single pillar sls file and render it

        NEW: Perform a depth-first resolution of include-ed pillar files.  As
        includes are processed, pillar dict() is built up on the fly, allowing
        for subsequent pillar dict() references in pillar_sls. Order of include
        processing is depth first, therefore defining the scoping rules.
        A side-effect is that to discover any include's the sls is compiled
        twice: incase there are any pillar dict refs to be defined.

        NEW: Perform a hierachical resolution of all sls files.
        Pass to client.get_state() a modified sls path, based on hieradb
        configured (see pillar_hieradb()). A depth first resolutoin is processed
        following a most-specific-path higher-precedence model.

        '''
        err = ''
        errors = []

        original_sls = sls
        hieradb_paths = []
        for path in self.pillar_hieradb:
            path = re.sub(r'%{sls}', sls, path)
            hieradb_paths.append(path)

        log.info("XXX sls: {0} hieradb: {1}".format(sls, hieradb_paths))

        total_paths = len(hieradb_paths)
        found_paths = 0
        state = None
        while hieradb_paths:
            # pop(): bottom up, where later settings are merged over earlier
            sls = hieradb_paths.pop()
            fn_ = self.client.get_state(sls, env)

            if not fn_:
                continue

            recompile_flag=False
            found_paths = found_paths + 1
            try:
                log.info("ZZZ <<< compile: {0}".format(fn_))
                state = compile_template(
                    fn_, self.rend, self.opts['renderer'], env, sls)
                log.debug("ZZZ >>> state: {0}".format(state))
                if state:
                    # Detect here if any pillar[tokens] were None?
                    for key,var in state.items():
                        if var is None:
                            recompile_flag=True
                            break
            except Exception as exc:
                errors.append(('Rendering SLS {0} failed, render error:\n{1}'
                               .format(sls, exc)))
            mods.add(sls)
            nstate = None
            if state:
                if not isinstance(state, dict):
                    errors.append(('SLS {0} does not render to a dictionary'
                                   .format(sls)))
                else:
                    if 'include' in state:
                        if not isinstance(state['include'], list):
                            err = ('Include Declaration in SLS {0} is not formed '
                                   'as a list'.format(sls))
                            errors.append(err)
                        else:
                            for sub_sls in state.pop('include'):
                                if sub_sls not in mods:
                                    log.info("rendering: {0}".format(sub_sls))
                                    nstate, mods, err = self.render_pstate(
                                            sub_sls,
                                            env,
                                            mods
                                            )
                                else:
                                    log.info("seen: {0}".format(sub_sls))

                                if err:
                                    errors += err
            if recompile_flag:
                try:
                    log.info("ZZZ <<< recompile: {0}".format(fn_))
                    state = compile_template(
                        fn_, self.rend, self.opts['renderer'], env, sls)
                    log.debug("ZZZ >>> state: {0}".format(state))
                except Exception as exc:
                    errors.append(('Rendering SLS {0} failed, render error:\n{1}'
                                   .format(sls, exc)))
            if state:
                _merge(self.opts['pillar'], state)

        if found_paths == 0:
            errors.append(('Specified SLS {0} in environment {1} is not'
                           ' available on the salt master').format(original_sls,
                                                                   env))
        log.debug("XXX render_pstate finish: {0}".format(self.opts['pillar']))
        return state, mods, errors

    def render_pillar(self, matches):
        '''
        Extract the sls pillar files from the matches and render them into the
        pillar
        '''
        errors = []
        for env, pstates in matches.items():
            mods = set()
            for sls in pstates:
                log.debug("XXX rendering_pstate {0} {1} {2}".format(sls, env, mods))
                pstate, mods, err = self.render_pstate(sls, env, mods)
                #if pstate:
                #    pillar.update(pstate)
                if err:
                    errors += err
        log.debug("XXX rendering_pillar returns {0} {1}".format(self.opts['pillar'], errors))

        # clean up private keys
        for private in self.pillar_hieradb_private_keys:
            if private in self.opts['pillar']:
                del(self.opts['pillar'][private])

        return self.opts['pillar'], errors

    def pillar_hieradb(self):
        '''
        Parse the 'pillar_hieradb' token from salt/master config.

        This configures a hierarchical data lookup for each minion, based on
        grains from on the minon system. The pillar sls files will be resolved
        in render_pstate() by the specified hierarchy and merged by _merge()
        function (see above).

        List of hieradb resolution paths, supporting grain substitution.

        pillar_hieradb:
          - %{grain1}.%{grain2}.%{sls}
          - %{grain1}.%{sls}
          - %{sls}

        '''

        self.pillar_hieradb = []
        if not "pillar_hieradb" in self.opts:
            return []
        if not isinstance(self.opts['pillar_hieradb'], list):
            log.critical('The "pillar_hieradb" option is malformed')
            return []
        for path in self.opts['pillar_hieradb']:
            # sub tokens for grains
            # stash lookup path
            for key, val in self.opts['grains'].items():
                if isinstance(val, string_types):
                    path = re.sub(r'%{' + key + '}', val, path)
            self.pillar_hieradb.append(path)

        # Configurable key list to be clipped from output to minion
        self.pillar_hieradb_private_keys = []
        if not "pillar_hieradb_private_keys" in self.opts:
            return []
        if not isinstance(self.opts['pillar_hieradb_private_keys'], list):
            log.critical('The "pillar_hieradb_private_keys" option is malformed')
            return []
        for path in self.opts['pillar_hieradb_private_keys']:
            self.pillar_hieradb_private_keys.append(path)

    def ext_pillar(self):
        '''
        Render the external pillar data
        '''
        if not 'ext_pillar' in self.opts:
            return  {}
        if not isinstance(self.opts['ext_pillar'], list):
            log.critical('The "ext_pillar" option is malformed')
            return {}
        ext = {}
        for run in self.opts['ext_pillar']:
            if not isinstance(run, dict):
                log.critical('The "ext_pillar" option is malformed')
                return {}
            for key, val in run.items():
                if key not in self.ext_pillars:
                    err = ('Specified ext_pillar interface {0} is '
                           'unavailable').format(key)
                    log.critical(err)
                    continue
                try:
                    if isinstance(val, dict):
                        ext.update(self.ext_pillars[key](**val))
                    elif isinstance(val, list):
                        ext.update(self.ext_pillars[key](*val))
                    else:
                        ext.update(self.ext_pillars[key](val))
                except Exception as e:
                    log.critical('Failed to load ext_pillar {0}'.format(key))
        return ext

    def compile_pillar(self):
        '''
        Render the pillar dta and return
        '''
        __pillar__ = { "else": "test1" }
        top, terrors = self.get_top()
        matches = self.top_matches(top)
        # perform new recursive, hieradb strategy
        pillar, errors = self.render_pillar(matches)
        # merge in any ext_pillar
        _merge(pillar, self.ext_pillar())
        errors.extend(terrors)
        if errors:
            for error in errors:
                log.critical('Pillar render error: {0}'.format(error))
            return {}
        log.debug("XXX pillar returned {0}".format(pillar))
        return pillar
