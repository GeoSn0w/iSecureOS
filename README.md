# iSecureOS

An iOS Security Application for Jailbroken devices. It does basic checks for repos you shouldn't trust, allows one to change the ROOT and mobile password, and provides general security information about vulnerabilities you may have on your device.

This tweak is currently in Beta 1 and it is expected to get much better with time.

Development for Dopamine 2 / Rootless Support has begun.

While this tweak aims to aid you in getting a better security strategy on your device, **this is not a real-time antivirus**.

### Features 

As of Beta 1 (v1.17~Beta1), the application has the following features:

* Detects the MainRepo Backdoor malware, right now there are two separate malware occurrences in the wild.
* While scanning, it can detect an active SSH connection or an attempted SSH connection via the network to your device.
* It can detect unsafe pirate repos that may have outdated, modified or otherwise not recommended tweaks. This check is done against a built-in list fetched from GitHub for ease of updating. The app does include an in-memory copy of the list to be able to work offline when there's no internet connection.
* Tells you some basic information about the overall security of the device: VPN, Location, Passcode, etc.
* Allows you to change the default ROOT and Mobile SSH password from the app itself.
* Lists major CVEs for your device/version that are actively exploited in the wild - This needs to be redone as a much larger database and it's in the PoC stage.
* Uses SHA-256 malware hashing and performs fast deep-scans which go system-wide.
* Quarantines malware on the spot when it finds it.

More features are yet to come, this is just Beta 1.

Found a vulnerability?
Please send an email at office [a t] fce365 dot info

### Recommendations

While this application aims to help you improve your jailbreak's security, this application is not an antivirus and it doesn't perform real-time scanning as of Beta 1. Maybe in the future, I might add background scanning, however, you should still use common sense and not install tweaks from unknown sources.

### Privacy policy

This application does not collect any user-identifiable data, does not send any logs or reports to my server and does not track you in any way.
This application also does not include any analytics or advertisements code. 

### Price
This application is completely free. It's also Open-Source.
If you paid for it, you have been scammed.

### Official repo
This application should only be downloaded from the official repo (https://isecureos.idevicecentral.com/repo) or compiled by yourself.

### Credits

This application was done entirely by GeoSn0w (@hiDeviceCentral), however, I'd like to credit **sarahh12099** for their bad repos list that is being used in the application.

### FAQ (Frequent Asked Questions)

Q: The app shows me CVE vulnerabilities. How can I fix them?
A: The CVE shown are informative. You cannot fix them without updating your iOS, which of course, you shouldn't do because you will lose your jailbreak. 
   These vulnerabilities are part of your iOS version, and many of them are the reason you can jailbreak in the first place. They are vulnerabilities nonetheless, so you should be careful.
   
Q: The app says I don't have a VPN. What VPN should I use?
A: We cannot make any VPN suggestions because that would be an endorsement. You should research well which kind of VPN works for you. We can say that you should go for a reputable, no logs, good privacy policy VPN.

Q: What if I want to keep using pirated repos?
A: Your choice. The app won't interfere with that and it won't delete anything.

### Compiling:

To compile properly, you need to modify Xcode to allow you to call system() on iOS. After you modify the header, uncomment the line in iSecureOS-Security.m

### Legal stuff

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### My Websites
* <a href="https://idevicecentral.com">Latest iOS 16 Jailbreak News</a>
* <a href="https://gametutorialpro.com">Latest Gaming News & Guides</a>
* <a href="https://jailbreak.fce365.info">iOS Jailbreak Forum</a>
* <a href="https://gsmbypass.com">Latest FRP Bypass Tools & Guides</a>
