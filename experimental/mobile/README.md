# Origin Social — Mobile App (Android + iOS)

React Native + Expo app that provides a full TikTok-style experience on both
Android and iOS, with built-in Origin Protocol content-ownership protection.

## Getting started

```bash
npm install
npx expo start          # starts Metro bundler + Expo DevTools
```

Then press:
- `a` — open Android emulator
- `i` — open iOS simulator
- Scan the QR code with the **Expo Go** app on a physical device

## Connecting to the server

By default the app connects to `http://localhost:4000/api`.  When running on a
physical device or emulator, update the `EXPO_PUBLIC_API_URL` environment
variable to point at your server's LAN IP address:

```bash
EXPO_PUBLIC_API_URL=http://192.168.1.10:4000/api npx expo start
```

## Build for production

```bash
npx eas build --platform android
npx eas build --platform ios
```

Requires an [Expo Application Services (EAS)](https://expo.dev/eas) account.

## Key screens

| Screen | Description |
|--------|-------------|
| Feed | Vertically scrollable video feed (infinite scroll) |
| Upload | Pick a video, add title/description, optionally link an Origin Bundle |
| Profile | View profile, see Origin-verified status, log out |
| Login / Register | JWT-based authentication |
