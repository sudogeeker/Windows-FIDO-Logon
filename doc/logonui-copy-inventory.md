# LogonUI 文案精修清单

更新日期：2026-09-07。下表为本轮精简后的源码文案；编号沿用首次盘点，便于继续逐条讨论。

范围：本项目 Credential Provider 的登录、解锁界面。Windows 自带系统文案不在本仓库中。英文和简体中文共用同一份 UiTextId 表，其中 SelectUserAndPassword 保留为空；Subtitle 仅为字段描述标签；产品大标题隐藏。

## 当前文案

| 编号 | UiTextId | 中文 | 英文 |
| --- | --- | --- | --- |
| L01 | Title | Windows FIDO 登录 | Windows FIDO Logon |
| L02 | Subtitle（小字字段描述标签） | 本地账户密码和安全密钥 | Local account password + security key |
| M01 | SelectUserAndPassword | （空） | （空） |
| L03 | LocalUserLabel | 本地用户 | Local user |
| L04 | WindowsPasswordLabel | Windows 密码 | Windows password |
| L05 | SecurityKeyPinLabel | 安全密钥 PIN | Security key PIN |
| L07 | NewPasswordLabel | 新 Windows 密码 | New Windows password |
| L08 | ConfirmPasswordLabel | 确认新密码 | Confirm new password |
| L09 | ContinueButton | 继续 | Continue |
| L10 | VerifyKeyButton | 验证安全密钥 | Verify security key |
| L11 | ChangePasswordButton | 修改密码 | Change password |
| M02 | SelectUserAndPasswordPrompt | 请输入本地用户名和密码。 | Enter your local username and password. |
| M03 | LocalAccountsOnly | 仅支持本地账户。 | Local accounts only. |
| M04 | SignInVerificationUnavailable | 无法启动登录验证。 | Unable to start sign-in verification. |
| M05 | MfaPolicyUnavailable | 无法验证 MFA 策略。 | Unable to verify MFA policy. |
| M06 | PreparingWindowsSignIn | 正在准备 Windows 登录… | Preparing Windows sign-in… |
| M07 | NoSecurityKeyDetected | 未检测到兼容的 USB 安全密钥。 | No compatible USB security key was detected. |
| M09 | EnterPinAndTouch | 请输入安全密钥 PIN。 | Enter the security key PIN. |
| M10 | TouchKey | 请触摸安全密钥。 | Touch your security key. |
| M11 | KeyVerificationFailed | 安全密钥验证失败。 | Security key verification failed. |
| M12 | KeyVerificationIncomplete | 安全密钥验证未能完成。 | Security-key verification could not be completed. |
| M13 | KeyVerified | 正在登录… | Signing in… |
| M14 | PasswordUpdateFailed | 无法完成密码修改。 | Unable to complete the password change. |
| M15 | PasswordMustChange | 请修改 Windows 密码。 | Your Windows password must be changed. |
| M16 | PasswordVerificationFailed | 密码验证失败。 | Password verification failed. |
| M17 | SignInFailed | 登录失败。 | Sign-in failed. |
| M18 | EnterPasswordPrompt | 请输入 Windows 密码。 | Enter your Windows password. |
| L12 | ProviderLabel | 密码和安全密钥 | Password and security key |

## 显示与重试行为

- FID_SMALL_TEXT 在用户名/密码、安全密钥和修改密码三个阶段均显示；绑定用户时初始内容为 M18，“其他用户”时为 M02，L02 只描述该字段本身，并非持久副标题。
- Connect 过程中的提示会同时通过 IQueryContinueWithStatus::SetStatusMessage 和 FID_SMALL_TEXT 提交给 LogonUI；后续消息会替换前一条，完整重置时恢复对应的初始提示。
- ReportResult 的主状态或子状态为 STATUS_WRONG_PASSWORD 时，在错误区返回 M16；其他一般失败返回 M17。STATUS_LOGON_FAILURE 本身不足以认定密码错误。
- 密码过期或必须修改时，在错误/警告区返回 M15；修改密码输入校验或打包失败仍返回 M14。
- PIN 转换为本次设备调用使用的临时值后，立即清空配置、字段缓冲区和 LogonUI 输入框；设备调用结束后清零临时值。
- 登录结果回调、断开/取消、切换用户、取消选择和完整重置都会清除对应 PIN 状态，不提供跨次复用。

## 来源与补充文字

- CredentialProvider/Localization.h：UiTextId。
- CredentialProvider/i18n/en-US.h、zh-CN.h：英文、中文原文。Localization.cpp 在编译时校验两份表的长度。
- CredentialProvider/core/CCredential.cpp：Connect、ReportResult、ClearPin 和字段行为。
- CredentialProvider/scenario.h：字段可见状态和默认描述标签。
- X01：提交按钮没有英文底层描述标签；UiFieldLabel 提供本地化默认标签，实际按钮字符串按阶段使用 L09/L10/L11。
- X02：LogonUI 不显示设备名称，也不提供设备下拉框。检测到多个密钥时，由用户触摸选定设备；PIN 和断言仅发送给该设备。
- 用户显示名称、头像和用户选择由 Windows 原生 LogonUI 提供。项目位图只用于登录选项图标，L12 为该图标的标签。
- “其他用户”按 Windows 账户选项显示用户名输入框；已绑定用户隐藏该输入框，直接聚焦密码。
- 用户名为动态内容，不是固定文案。

## 触发条件说明

- M06 在交给 Windows 验证密码前显示，不表示密码已通过。
- M07 表示没有枚举到可用的 USB FIDO2/ES256 设备，不推断账户的注册状态。
- M04 和 M12 均覆盖多种 Broker、传输或验证故障，因此不归因于单一策略或服务拒绝。
- M14 覆盖新密码为空、不一致及其他密码修改打包失败；M16 仅在 Windows 返回明确的 `STATUS_WRONG_PASSWORD` 时显示，但文案不将其扩展为其他结论。

验证：CredentialUiTests 覆盖错误分类、小字字段的运行时替换、设备选择控件不存在和 PIN 清空通知；真实安全桌面与 USB 设备的显示时序按 doc/test-plan.md 手动验证。
