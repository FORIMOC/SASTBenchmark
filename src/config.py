from dynaconf import Dynaconf

SETTINGS = Dynaconf(
    settings_file=["src/config/default.toml"],
)