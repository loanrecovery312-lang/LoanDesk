# LoanDesk Android app shell

This is a native Android launcher shell for the LoanDesk customer web app. The customer UI and API are served by the backend, so the shell must point to a real server URL.

## Local testing

1. Start the backend from the root project folder: `./run-local.sh` (macOS/Linux) or `run-local.bat` (Windows).
2. Open `android-app` in Android Studio and let Gradle sync.
3. The default `APP_URL` in `gradle.properties` is `http://10.0.2.2:8000/app`, which points an Android emulator to the backend on the host computer.
4. Run the **debug** build on an emulator. Debug permits cleartext HTTP only for local testing.
5. For a physical phone, change `APP_URL` to the host computer's LAN URL (for example `http://192.168.1.25:8000/app`) and set `HOST=0.0.0.0` in `.env`. Keep the phone and computer on a trusted private network. Do not use this HTTP setup on a public network.

## Release build

Before making a release APK, host the backend behind HTTPS, configure a real SMS provider, and set `APP_URL` to `https://your-real-domain/app`. The release manifest disallows cleartext traffic. Never put SMS credentials, database credentials, admin passwords, encryption keys, or OTP secrets into the Android app.

A compiled APK is not included because this workspace does not have the Android SDK/Gradle build environment installed. Android Studio can build it from this source project.
