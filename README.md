# iSecureOS Beta 1

An iOS Security Application for Jailbroken devices. It does basic checks for repos you shouldn't trust, allows one to change the ROOT and mobile password, and provides general security information about vulnerabilities you may have on your device.

This tweaks is currently in Beta 1 and it is expected to get much better with time.

While this tweak aims to aid you in getting a better security strategy on your device, **this is not a real-time antivirus**.

### Features

As of Beta 1 (v1.08~Beta1), the application has the following features:

* While scanning, it can detect an active SSH connection, or an attempted SSH connection via the network to your device.
* It can detect unsafe pirate repos that may have outdated, modified or otherwise not recommended tweaks. This check is done against a built-in list fetched from GitHub for ease of updating. The app does include an in-memory copy of the list to be able to work offline when there's no internet connection.
* Tells you some basic information about the overal security of the device: VPN, Location, Passcode, etc.
* Allows you to change the default ROOT and Mobile SSH password from the app itself.
* Lists major CVEs for your device / version that are actively exploited in the wild - This needs to be redone as a much larger database and it's in the PoC stage.

More features are yet to come, this is just Beta 1.

### Recommendations

While this application aims to help you improve your jailbreak's security, this application is not an antivirus and it doesn't perform real-time scanning as of Beta 1. Maybe in the future, I might add background scanning, however, you should still use common sense and not install tweaks from unknown sources.

### Credits

this application was done entirely by GeoSn0w (@FCE365), however, I'd like to credit **sarahh12099** for their bad repos list that is being used in the application.
