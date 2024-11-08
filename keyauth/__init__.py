from .api import mainapi
from .hwid import WINDOWS_HWID
from os import _exit, system
from json import loads

def sys_hwid() -> str:
    '''
    this def will return a hardware id,
    hardware id is a unique key use for key auth
    this will return a unique hwid key depend on os
    supported os -> window, darwin, linux
    '''
    return WINDOWS_HWID().main()

def api(name=None, ownerid=None, version=None, hash_to_check=None):
    '''
    :param name: Name of the app.
    :param ownerid: Account ID.
    :param version: Application version.
    :param hash_to_check: value of MD5 checksum (hash) of a file.
    '''
    instance = mainapi(
        name=name,
        ownerid=ownerid,
        version=version,
        hash_to_check=hash_to_check
    )
    return instance
