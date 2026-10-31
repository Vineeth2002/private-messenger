#!/usr/bin/env bash
set -Eeuo pipefail

# This script must be run as one Bash process. The android-emulator-runner
# action parses its `script:` input line-by-line and invokes each line via sh.

echo "Checking Android Debug Bridge..."
adb version
adb devices -l
adb wait-for-device

echo "Waiting for the Android package service..."
PACKAGE_SERVICE_READY=false

for attempt in {1..60}; do
  if adb shell service check package 2>/dev/null | grep -q 'found'; then
    PACKAGE_SERVICE_READY=true
    break
  fi

  sleep 2
done

if [[ "$PACKAGE_SERVICE_READY" != true ]]; then
  echo "::error::Android package service did not become ready."
  adb devices -l || true
  adb logcat -d -t 500 || true
  exit 1
fi

echo "Installing debug APK..."

if ! adb install -r app/build/outputs/apk/debug/app-debug.apk; then
  echo "::error::APK installation failed."
  adb devices -l || true
  adb logcat -d -t 500 || true
  exit 1
fi

adb shell am force-stop org.sovereign.pm || true
adb logcat -c

echo "Starting the application..."
adb shell am start -W -n org.sovereign.pm/.MainActivity

sleep 5

if ! adb shell pidof org.sovereign.pm; then
  echo "::error::Application process was not found after startup."
  adb logcat -d -t 500 || true
  exit 1
fi

sleep 3

if ! adb shell pidof org.sovereign.pm; then
  echo "::error::Application process did not remain running."
  adb logcat -d -t 500 || true
  exit 1
fi

adb shell uiautomator dump /sdcard/pm-window.xml
adb pull /sdcard/pm-window.xml pm-window.xml

grep -Fq 'UniFFI canonical CBOR: PASS' pm-window.xml
grep -Fq 'Identity storage: CREATED_AND_PERSISTED' pm-window.xml
grep -Fq 'At-rest encryption: PASS' pm-window.xml

echo "PASS: app launched, UniFFI CBOR passed, identity storage persisted, and at-rest encryption passed."
