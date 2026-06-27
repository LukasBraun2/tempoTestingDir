# Tempo — Local Server with Google Sign-In

A self-hosted version of the Tempo time tracker. Students sign in with their real Google accounts. All data is stored on your computer in `data/tempo.json`.

---

## Step 1 — Get Google OAuth credentials (5 minutes)

1. Go to [https://console.cloud.google.com](https://console.cloud.google.com)
2. Click **Select a project** → **New Project**, name it "Tempo" → Create
3. In the left menu: **APIs & Services** → **Credentials**
4. Click **+ Create Credentials** → **OAuth client ID**
   - If prompted to configure a consent screen first:
     - User Type: **External** → Create
     - App name: "Tempo", fill in your email → Save and Continue through all steps
5. Application type: **Web application**, name it anything
6. Under **Authorized redirect URIs**, click **+ Add URI** and add:
   ```
   http://localhost:3000/auth/google/callback
   ```
   (Add more URIs here later if you use a different URL or ngrok)
7. Click **Create** — you'll see your **Client ID** and **Client Secret**

---

## Step 2 — Configure the app

Copy the example env file and fill it in:
```bash
cp .env.example .env
```

Edit `.env`:
```
GOOGLE_CLIENT_ID=123456789-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxx
BASE_URL=http://localhost:3000
SESSION_SECRET=any-long-random-string-here
```

---

## Step 3 — Run it

```bash
npm install
npm start
```

Open **http://localhost:3000** — students click "Continue with Google" and get a real Google sign-in popup.

---

## Admin panel

Open **http://localhost:3000/admin.html**

Default password: `admin123` — change it in `data/config.json` after first run.

---

## Sharing with students on the same network

1. Find your local IP: `ipconfig` (Windows) or `ifconfig` (Mac/Linux)
2. Update `BASE_URL` in `.env` to `http://YOUR-IP:3000`
3. Add `http://YOUR-IP:3000/auth/google/callback` to your Google OAuth authorized redirect URIs
4. Share `http://YOUR-IP:3000` with students

## Sharing over the internet (ngrok)

1. Install [ngrok](https://ngrok.com/) and run: `ngrok http 3000`
2. Copy the `https://xxxx.ngrok.io` URL
3. Set `BASE_URL=https://xxxx.ngrok.io` in `.env`
4. Add `https://xxxx.ngrok.io/auth/google/callback` to your Google OAuth redirect URIs
5. Restart the server

---

## Data

All data lives in `data/tempo.json`. Back it up regularly!
