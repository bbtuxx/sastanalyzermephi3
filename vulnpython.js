{
    "vulnerabilities": [
        {
            "name": "eval",
            "description": "Использование eval может привести к выполнению произвольного кода.",
            "recommendation": "Избегайте использования eval и используйте безопасные альтернативы.",
            "pattern": ".*eval\\(.*\\).*",
            "search_query": "how to avoid using eval in python"
        },
        {
            "name": "exec",
            "description": "Использование exec может привести к выполнению произвольного кода.",
            "recommendation": "Избегайте использования exec и используйте безопасные альтернативы.",
            "pattern": ".*exec\\(.*\\).*",
            "search_query": "how to avoid using exec in python"
        },
        {
            "name": "os.system",
            "description": "Использование os.system может привести к выполнению командной строки с произвольными данными.",
            "recommendation": "Используйте subprocess вместо os.system для выполнения команд.",
            "pattern": ".*os\\.system\\(.*\\+.*\\).*",
            "search_query": "how to avoid using os.system in python"
        },
        {
            "name": "pickle.load",
            "description": "Использование pickle.load на недоверенных данных может привести к выполнению произвольного кода.",
            "recommendation": "Используйте безопасные форматы данных, такие как JSON.",
            "pattern": ".*pickle\\.load\\(.*\\).*",
            "search_query": "how to avoid using pickle.load in python"
        },
        {
            "name": "input",
            "description": "Использование input в Python 2 может привести к выполнению произвольного кода.",
            "recommendation": "Используйте raw_input вместо input в Python 2.",
            "pattern": ".*input\\(.*\\).*",
            "search_query": "how to securely use input in python"
        }
    ]
}
