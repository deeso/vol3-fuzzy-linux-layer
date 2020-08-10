# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import re
import logging
from typing import List, Optional, Tuple, Type

from volatility.framework import interfaces, constants, exceptions
from volatility.framework import objects
from volatility.framework.automagic import symbol_cache, symbol_finder
from volatility.framework.automagic.linux import LinuxBannerCache, LinuxSymbolFinder, LinuxIntelStacker
from volatility.framework.symbols.linux import LinuxUtilities
from volatility.framework.layers import intel, scanners
from volatility.framework.symbols import linux

vollog = logging.getLogger(__name__)


class FuzzyLinuxIntelStacker(LinuxIntelStacker):
    stack_order = 46
    exclusion_list = ['mac', 'windows']
    LINUX_VERSION_REGEX = rb'Linux version\s\d+\.\d+\.\d+-\d+-\w+'
    MAX_KERNEL_BANNER_LEN = 1024
    LINUX_CAPTURE_REGEX = rb'Linux version\s(?P<release>\d+\.\d+\.\d+-\d+-\w+)'
    RE_EXTRACTOR = re.compile(LINUX_CAPTURE_REGEX)
    LINUX_DISTROS = [b'ubuntu', b'redhat', b'debian', b'centos', b'fedora']
    DEFAULT_MATCH_KEYS = ['distro', 'tag', 'version']
    
    @classmethod
    def scan_generator(cls, context, layer, progress_callback, signature=LINUX_VERSION_REGEX):
        # borrowed this approach from the automagic mac version scanner
        for offset in layer.scan(scanner = scanners.RegExScanner(signature),
                                 context = context,
                                 progress_callback = progress_callback):
            banner_data = layer.read(offset, cls.MAX_KERNEL_BANNER_LEN)
            if banner_data.find(b'\n\x00') == -1:
                banner = None
            else:
                banner = banner_data[:banner_data.find(b'\n\x00')]
            yield offset, banner

    @classmethod
    def build_dtb_layer(cls, context, layer_name, progress_callback, banner, symbol_files):
        join = interfaces.configuration.path_join
        layer, dtb = (None, None)
        if symbol_files is None:
            return layer, dtb

        isf_path = symbol_files[0]
        table_name = context.symbol_space.free_table_name('LintelStacker')
        table = linux.LinuxKernelIntermedSymbols(context,
                                                 'temporary.' + table_name,
                                                 name = table_name,
                                                 isf_url = isf_path)
        context.symbol_space.append(table)
        kaslr_shift, _ = LinuxUtilities.find_aslr(context,
                                                  table_name,
                                                  layer_name,
                                                  progress_callback = progress_callback)

        layer_class = intel.Intel  # type: Type
        if 'init_top_pgt' in table.symbols:
            layer_class = intel.Intel32e
            dtb_symbol_name = 'init_top_pgt'
        elif 'init_level4_pgt' in table.symbols:
            layer_class = intel.Intel32e
            dtb_symbol_name = 'init_level4_pgt'
        else:
            dtb_symbol_name = 'swapper_pg_dir'

        dtb = LinuxUtilities.virtual_to_physical_address(
            table.get_symbol(dtb_symbol_name).address + kaslr_shift)

        # Build the new layer
        new_layer_name = context.layers.free_layer_name("IntelLayer")
        config_path = join("IntelHelper", new_layer_name)
        context.config[join(config_path, "memory_layer")] = layer_name
        context.config[join(config_path, "page_map_offset")] = dtb
        context.config[join(config_path, LinuxSymbolFinder.banner_config_key)] = str(banner, 'latin-1')

        layer = layer_class(context, config_path = config_path, name = new_layer_name)
        return layer, dtb

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]
        join = interfaces.configuration.path_join
        if 'LintelStacker' in context.layers:
            return None
        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel) or isinstance(layer, LinuxIntelStacker):
            return None
        
        vollog.warning("Performing fuzzy search and match on Linux Kernel Symbols")
        linux_banners = LinuxBannerCache.load_banners()
        # If we have no banners, don't bother scanning
        if not linux_banners:
            vollog.info("No Linux banners found - if this is a linux plugin, please check your symbol files location")
            return None
        
        linux_banner_infos = {k: cls.extract_version(k) for k in linux_banners.keys() if k is not None}
        linux_banner_infos = {k: v for k, v in linux_banner_infos.items() if v['release']}
        # Use a basic regular expression to hunt for a Linux Kernel Banner
        for offset, banner in cls.scan_generator(context, layer, progress_callback):
            if banner is None:
                continue
            # Banner found, extract out relevant bits
            banner_info = cls.extract_version(banner) 
            # try to find a candidate symbol table with the right version, tag (e.g. generic, kvm, etc.), distro
            match = cls.check_candidates(banner_info, linux_banner_infos, match_keys=cls.DEFAULT_MATCH_KEYS)
            if match is None:
                continue
            banner = match
            symbol_files = linux_banners.get(match, None)
            if symbol_files is None:
                continue

            # potential match, hope it doesn't explode :S
            vollog.warning("Identified banner using fuzzy approach: {}".format(repr(banner)))
            layer, dtb = cls.build_dtb_layer(context, layer_name, progress_callback, 
                                             banner, symbol_files)
            if layer and dtb:
                vollog.warning("DTB was found using fuzzy approach at: 0x{:0x}".format(dtb))
                return layer
        return None

    @classmethod
    def extract_version(cls, vstr):
        info = {
            'distro': b'',
            'release': None,
            'tag': b'',
            'version': b'',
        }
                      
        if vstr.find(b'Linux version') == -1:
            return info
        r = cls.RE_EXTRACTOR.match(vstr)
        if r is None:
            return info

        info = r.groupdict()
        info['tag'] = info['release'].split(b'-')[-1]
        info['version'] = info['release'].split(b'-')[0]
        info['distro'] = b'' 

        lvstr = vstr.lower()
        for i in cls.LINUX_DISTROS:
            if lvstr.find(i) > -1:
                info['distro'] = i
                break
        return info

    @classmethod
    def check_candidates(cls, target_banner_info, known_banner_infos_dict, match_keys):
        for k_banner, k_banner_info in known_banner_infos_dict.items():
            if all(target_banner_info[k] == k_banner_info[k] for k in match_keys):
                return k_banner
        return None

    
