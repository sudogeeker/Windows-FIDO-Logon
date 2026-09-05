# Login languages

The credential provider currently ships with `en-US` and `zh-CN` text files.
The system UI language selects the table at runtime; unsupported languages fall back to `en-US`.
To add a language, add one header with the same `UiTextId` order and add its language mapping in `Localization.cpp`.
