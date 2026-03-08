"""
Ransomware Detection API - Feature Extractor Module

Extracts PE (Portable Executable) file features for ransomware detection.
Uses pefile library to parse and analyze Windows executables.
"""

import pefile
import math
import numpy as np
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Feature columns matching the trained model (50 features in exact order)
FEATURE_COLUMNS = [
    'Machine', 'TimeDateStamp', 'SizeOfOptionalHeader', 'Characteristics', 'Magic',
    'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
    'AddressOfEntryPoint', 'MinorSubsystemVersion', 'SizeOfImage', 'CheckSum',
    'DllCharacteristics', 'SizeOfStackReserve',
    # .text section features
    'text_Misc_VirtualSize', 'text_SizeOfRawData', 'text_Characteristics',
    # .data section features
    'data_Misc_VirtualSize', 'data_VirtualAddress', 'data_SizeOfRawData',
    'data_PointerToRawData', 'data_Characteristics',
    # .rdata section features
    'rdata_Misc_VirtualSize', 'rdata_PointerToRawData',
    # .bss section features
    'bss_Misc_VirtualSize', 'bss_VirtualAddress', 'bss_Characteristics',
    # .idata section features
    'idata_Misc_VirtualSize', 'idata_VirtualAddress', 'idata_SizeOfRawData',
    'idata_PointerToRawData', 'idata_Characteristics',
    # .rsrc section features
    'rsrc_Misc_VirtualSize', 'rsrc_VirtualAddress', 'rsrc_SizeOfRawData', 'rsrc_PointerToRawData',
    # .reloc section features
    'reloc_Misc_VirtualSize', 'reloc_VirtualAddress', 'reloc_SizeOfRawData', 'reloc_PointerToRawData',
    # .tls section features
    'tls_Misc_VirtualSize', 'tls_VirtualAddress', 'tls_PointerToRawData', 'tls_Characteristics',
    # .pdata section features
    'pdata_Misc_VirtualSize', 'pdata_VirtualAddress', 'pdata_SizeOfRawData',
    'pdata_PointerToRawData', 'pdata_Characteristics'
]

# Section names to extract features from
SECTION_NAMES = ['text', 'data', 'rdata', 'bss', 'idata', 'rsrc', 'reloc', 'tls', 'pdata']

# Section feature mappings
SECTION_FEATURES = {
    'text': ['Misc_VirtualSize', 'SizeOfRawData', 'Characteristics'],
    'data': ['Misc_VirtualSize', 'VirtualAddress', 'SizeOfRawData', 'PointerToRawData', 'Characteristics'],
    'rdata': ['Misc_VirtualSize', 'PointerToRawData'],
    'bss': ['Misc_VirtualSize', 'VirtualAddress', 'Characteristics'],
    'idata': ['Misc_VirtualSize', 'VirtualAddress', 'SizeOfRawData', 'PointerToRawData', 'Characteristics'],
    'rsrc': ['Misc_VirtualSize', 'VirtualAddress', 'SizeOfRawData', 'PointerToRawData'],
    'reloc': ['Misc_VirtualSize', 'VirtualAddress', 'SizeOfRawData', 'PointerToRawData'],
    'tls': ['Misc_VirtualSize', 'VirtualAddress', 'PointerToRawData', 'Characteristics'],
    'pdata': ['Misc_VirtualSize', 'VirtualAddress', 'SizeOfRawData', 'PointerToRawData', 'Characteristics']
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    entropy = 0.0
    data_len = len(data)
    
    # Count byte frequencies
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy
    for count in freq.values():
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    
    return entropy


def get_section_entropy(pe: pefile.PE, section) -> float:
    """Calculate entropy for a PE section."""
    try:
        data = section.get_data()
        return calculate_entropy(data)
    except Exception:
        return 0.0


def extract_features(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract features from a PE file.
    
    Args:
        file_path: Path to the PE file
        
    Returns:
        Dictionary of features or None if extraction fails
    """
    try:
        pe = pefile.PE(file_path)
        features = {}
        
        # DOS Header and PE Header features
        features['Machine'] = pe.FILE_HEADER.Machine
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        # Optional Header features
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        
        # BaseOfData only exists in 32-bit PE files
        features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
        
        features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        
        # Section features
        sections = pe.sections
        features['SectionsNb'] = len(sections)
        
        if sections:
            entropies = [get_section_entropy(pe, s) for s in sections]
            raw_sizes = [s.SizeOfRawData for s in sections]
            virtual_sizes = [s.Misc_VirtualSize for s in sections]
            
            features['SectionsMeanEntropy'] = np.mean(entropies) if entropies else 0.0
            features['SectionsMinEntropy'] = min(entropies) if entropies else 0.0
            features['SectionsMaxEntropy'] = max(entropies) if entropies else 0.0
            features['SectionsMeanRawsize'] = np.mean(raw_sizes) if raw_sizes else 0.0
            features['SectionsMinRawsize'] = min(raw_sizes) if raw_sizes else 0.0
            features['SectionMaxRawsize'] = max(raw_sizes) if raw_sizes else 0.0
            features['SectionsMeanVirtualsize'] = np.mean(virtual_sizes) if virtual_sizes else 0.0
            features['SectionsMinVirtualsize'] = min(virtual_sizes) if virtual_sizes else 0.0
            features['SectionMaxVirtualsize'] = max(virtual_sizes) if virtual_sizes else 0.0
        else:
            features['SectionsMeanEntropy'] = 0.0
            features['SectionsMinEntropy'] = 0.0
            features['SectionsMaxEntropy'] = 0.0
            features['SectionsMeanRawsize'] = 0.0
            features['SectionsMinRawsize'] = 0.0
            features['SectionMaxRawsize'] = 0.0
            features['SectionsMeanVirtualsize'] = 0.0
            features['SectionsMinVirtualsize'] = 0.0
            features['SectionMaxVirtualsize'] = 0.0
        
        # Import features
        imports_nb_dll = 0
        imports_nb = 0
        imports_nb_ordinal = 0
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports_nb_dll = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports_nb += len(entry.imports)
                for imp in entry.imports:
                    if imp.name is None:
                        imports_nb_ordinal += 1
        
        features['ImportsNbDLL'] = imports_nb_dll
        features['ImportsNb'] = imports_nb
        features['ImportsNbOrdinal'] = imports_nb_ordinal
        
        # Export features
        features['ExportNb'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        
        # Resource features
        resources_nb = 0
        resources_entropies = []
        resources_sizes = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            def count_resources(resource_entry):
                nonlocal resources_nb, resources_entropies, resources_sizes
                if hasattr(resource_entry, 'directory'):
                    for entry in resource_entry.directory.entries:
                        count_resources(entry)
                elif hasattr(resource_entry, 'data'):
                    resources_nb += 1
                    try:
                        data = pe.get_data(resource_entry.data.struct.OffsetToData, 
                                          resource_entry.data.struct.Size)
                        resources_entropies.append(calculate_entropy(data))
                        resources_sizes.append(resource_entry.data.struct.Size)
                    except Exception:
                        pass
            
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                count_resources(entry)
        
        features['ResourcesNb'] = resources_nb
        features['ResourcesMeanEntropy'] = np.mean(resources_entropies) if resources_entropies else 0.0
        features['ResourcesMinEntropy'] = min(resources_entropies) if resources_entropies else 0.0
        features['ResourcesMaxEntropy'] = max(resources_entropies) if resources_entropies else 0.0
        features['ResourcesMeanSize'] = np.mean(resources_sizes) if resources_sizes else 0.0
        features['ResourcesMinSize'] = min(resources_sizes) if resources_sizes else 0.0
        features['ResourcesMaxSize'] = max(resources_sizes) if resources_sizes else 0.0
        
        # Load Configuration Size
        features['LoadConfigurationSize'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        
        # Version Information Size
        features['VersionInformationSize'] = 0
        if hasattr(pe, 'VS_VERSIONINFO'):
            features['VersionInformationSize'] = len(pe.VS_VERSIONINFO)
        elif hasattr(pe, 'FileInfo'):
            # Try to get version info size from FileInfo
            features['VersionInformationSize'] = len(str(pe.FileInfo)) if pe.FileInfo else 0
        
        pe.close()
        return features
        
    except pefile.PEFormatError as e:
        logger.error(f"Not a valid PE file: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return None


def extract_features_from_bytes(file_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract features from PE file bytes for the new 50-feature model.
    
    Args:
        file_bytes: Raw bytes of the PE file
        
    Returns:
        Dictionary of features or None if extraction fails
    """
    try:
        pe = pefile.PE(data=file_bytes)
        features = {}
        
        # FILE_HEADER features
        features['Machine'] = pe.FILE_HEADER.Machine
        features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        # OPTIONAL_HEADER features
        features['Magic'] = pe.OPTIONAL_HEADER.Magic
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        
        # Build section lookup dictionary
        section_data = {}
        for section in pe.sections:
            # Normalize section name (e.g., '.text' -> 'text')
            try:
                name = section.Name.decode('utf-8').strip('\x00').strip('.').lower()
            except:
                name = ""
            if name:
                section_data[name] = section
        
        # Extract section-specific features
        for section_name in SECTION_NAMES:
            section = section_data.get(section_name)
            for attr in SECTION_FEATURES[section_name]:
                feature_name = f"{section_name}_{attr}"
                if section:
                    features[feature_name] = getattr(section, attr, 0)
                else:
                    features[feature_name] = 0
        
        pe.close()
        return features
        
    except pefile.PEFormatError as e:
        logger.error(f"Not a valid PE file: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return None
