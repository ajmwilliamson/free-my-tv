package io.freemytv;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Trakt (trakt.tv): the watchlist as the picks. Sign-in is OAuth's device flow (a code on the TV, typed at
 * auth.trakt.tv/activate): Trakt's apps are public PKCE clients since October 2026, with a Client ID and no secret, and
 * the device flow and the refresh take the Client ID alone (Trakt's own Android TV app does the same).
 *
 * The tokens stay on the TV, in trakt.json, and never go to the log. Refresh tokens work once: the home screen (:home)
 * and, on Android 11 to 12L, the screensaver (the main process) both fetch picks, so a refresh happens under a file
 * lock and reads the file again inside it.
 */
final class Trakt {
    private Trakt() {}

    private static final String API = "https://api.trakt.tv";
    /** Refresh needs the app's redirect URI; a device sign-in has none of its own, so these are tried in order. */
    private static final String[] REDIRECTS = {"urn:ietf:wg:oauth:2.0:oob", "http://localhost"};
    private static final String FILE = "trakt.json", LOCK_FILE = "trakt.lock";
    /** One thread at a time in this process; the file lock is for the other process. */
    private static final Object LOCK = new Object();

    static final int WAITING = 0, SIGNED_IN = 1, SLOW_DOWN = 2;

    /** A Client ID is built in (config.properties: trakt_client_id). */
    static boolean configured() {
        return !clientId().isEmpty();
    }

    private static String clientId() {
        return Config.TRAKT_CLIENT_ID.trim();
    }

    /** A sign-in code: `user` is what the person types, `url` where; `device` stays in the app. */
    static final class Code {
        String device, user, url;
        long expiresAt;
        int interval;
    }

    /** Off the UI thread: a new code to show. */
    static Code newCode() throws IOException, JSONException {
        Response r = call("POST", "/oauth/device/code", new JSONObject().put("client_id", clientId()), null);
        if (r.code != 200) throw new IOException("Trakt returned HTTP " + r.code);
        JSONObject o = new JSONObject(r.body);
        Code code = new Code();
        code.device = o.getString("device_code");
        code.user = o.getString("user_code");
        code.url = o.optString("verification_url", "https://trakt.tv/activate");
        code.expiresAt = System.currentTimeMillis() + o.optLong("expires_in", 600) * 1000L;
        code.interval = Math.max(1, o.optInt("interval", 5));
        return code;
    }

    /**
     * Off the UI thread: asks once whether the code was entered. WAITING, SLOW_DOWN or SIGNED_IN (the tokens are then
     * saved); Ended says why the code can't work any more (expired, refused, used), another IOException is the network.
     */
    static int poll(Context c, Code code) throws IOException, JSONException {
        Response r = call("POST", "/oauth/device/token",
                new JSONObject().put("code", code.device).put("client_id", clientId()), null);
        switch (r.code) {
            case 200: {
                JSONObject tokens = tokens(new JSONObject(r.body));
                tokens.put("user", username(tokens.getString("access")));
                synchronized (LOCK) {
                    try (Held ignored = lock(c)) {
                        write(c, tokens);
                    }
                }
                AppLog.w("trakt: signed in");
                return SIGNED_IN;
            }
            case 400: return WAITING;
            case 429: return SLOW_DOWN;
            case 404: throw new Ended("this code isn't Trakt's");
            case 409: throw new Ended("this code was already used");
            case 410: throw new Ended(EXPIRED);
            case 418: throw new Ended(DENIED);
            default: throw new IOException("Trakt returned HTTP " + r.code);
        }
    }

    static final String EXPIRED = "expired", DENIED = "denied";

    /** The code can't work any more (expired, refused, used): unlike a network error, asking again won't help. */
    static final class Ended extends IOException {
        Ended(String why) { super(why); }
    }

    /** The signed-in account's name, or "" when signed out. Cheap enough for a settings screen. */
    static String user(Context c) {
        JSONObject t = read(c);
        return t == null ? "" : t.optString("user", "?");
    }

    static boolean signedIn(Context c) {
        return read(c) != null;
    }

    /** Off the UI thread: forgets the tokens here, then tells Trakt (a failure there changes nothing on the TV). */
    static void signOut(Context c) {
        JSONObject t;
        synchronized (LOCK) {
            t = read(c);
            try (Held ignored = lock(c)) {
                new File(c.getFilesDir(), FILE).delete();
            } catch (IOException e) {
                new File(c.getFilesDir(), FILE).delete();
            }
        }
        AppLog.w("trakt: signed out");
        if (t == null) return;
        try {
            Response r = call("POST", "/oauth/revoke",
                    new JSONObject().put("token", t.optString("access")).put("client_id", clientId()), null);
            if (r.code != 200) AppLog.w("trakt: revoke: HTTP " + r.code);
        } catch (Exception e) {
            AppLog.w("trakt: revoke: " + e.getMessage());
        }
    }

    /**
     * Off the UI thread: the watchlist's movies ("movies") or shows ("shows"), in Trakt's order, up to 100, as
     * {tmdb id, imdb id or "", title}. Throws when signed out or Trakt can't be reached.
     */
    static List<String[]> watchlist(Context c, String type) throws IOException, JSONException {
        String access = accessToken(c, false);
        if (access == null) throw new IOException("not signed in");
        Response r = call("GET", "/sync/watchlist/" + type + "?page=1&limit=100", null, access);
        if (r.code != 200) throw new IOException("Trakt returned HTTP " + r.code);
        JSONArray items = new JSONArray(r.body);
        String one = type.equals("movies") ? "movie" : "show";
        List<String[]> out = new ArrayList<>();
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.optJSONObject(i), m = item == null ? null : item.optJSONObject(one);
            JSONObject ids = m == null ? null : m.optJSONObject("ids");
            if (ids == null || ids.optInt("tmdb") <= 0) continue;   // no TMDB id: no photos for it
            out.add(new String[] {String.valueOf(ids.optInt("tmdb")), ids.isNull("imdb") ? "" : ids.optString("imdb"),
                    m.optString("title")});
        }
        return out;
    }

    /**
     * The access token, refreshed first once half its life has gone (Trakt's last one or two days, so a TV that's
     * on now and then keeps it). Null when signed out, or when Trakt refused the refresh (then signed out here too).
     */
    private static String accessToken(Context c, boolean force) throws IOException {
        synchronized (LOCK) {
            try (Held ignored = lock(c)) {
                JSONObject t = read(c);   // again inside the lock: the other process may have just refreshed
                if (t == null) return null;
                long now = System.currentTimeMillis(), at = t.optLong("at"), life = t.optLong("life");
                if (!force && now >= at && now < at + life / 2) return t.optString("access");
                for (String redirect : REDIRECTS) {
                    Response r;
                    try {
                        r = call("POST", "/oauth/token", new JSONObject().put("refresh_token", t.getString("refresh"))
                                .put("client_id", clientId()).put("redirect_uri", redirect)
                                .put("grant_type", "refresh_token"), null);
                    } catch (JSONException e) {
                        throw new IOException(e.getMessage());
                    }
                    if (r.code == 200) {
                        JSONObject fresh = tokens(new JSONObject(r.body)).put("user", t.optString("user"));
                        write(c, fresh);
                        AppLog.w("trakt: token refreshed");
                        return fresh.getString("access");
                    }
                    AppLog.w("trakt: refresh: HTTP " + r.code);
                    if (r.code != 400 && r.code != 401) break;   // Trakt or the network, not this request: try later
                }
                // Not refreshed: the old token still works until it expires; after that, sign in again.
                if (now < at + life) return t.optString("access");
                new File(c.getFilesDir(), FILE).delete();
                AppLog.w("trakt: the sign-in expired");
                return null;
            } catch (JSONException e) {
                throw new IOException(e.getMessage());
            }
        }
    }

    /**
     * Off the UI thread, once right after signing in: refreshes the token at once, so a refresh Trakt refuses shows in
     * the log on day one, not when the token runs out. The token in use stays valid either way.
     */
    static void checkRefresh(Context c) {
        try {
            accessToken(c, true);
        } catch (IOException e) {
            AppLog.w("trakt: refresh check: " + e.getMessage());
        }
    }

    /** What to keep from a token answer: the tokens, when it was made and how long it lasts (ms). */
    private static JSONObject tokens(JSONObject o) throws JSONException {
        long created = o.optLong("created_at", 0) * 1000L;
        long now = System.currentTimeMillis();
        return new JSONObject().put("access", o.getString("access_token")).put("refresh", o.getString("refresh_token"))
                .put("at", created > 0 && created <= now ? created : now)
                .put("life", o.optLong("expires_in", 86400) * 1000L);
    }

    private static String username(String access) {
        try {
            Response r = call("GET", "/users/settings", null, access);
            if (r.code == 200) {
                JSONObject user = new JSONObject(r.body).optJSONObject("user");
                if (user != null) return user.optString("username", "?");
            }
        } catch (Exception e) {
            AppLog.w("trakt: user: " + e.getMessage());
        }
        return "?";
    }

    // MARK: - The file (written whole, then renamed: the other process never reads half of it)

    /** The file lock, held until close() (which also closes the file: the lock alone would leave it open). */
    private static final class Held implements AutoCloseable {
        private final RandomAccessFile file;

        Held(RandomAccessFile file) { this.file = file; }

        @Override public void close() throws IOException { file.close(); }
    }

    private static Held lock(Context c) throws IOException {
        RandomAccessFile file = new RandomAccessFile(new File(c.getFilesDir(), LOCK_FILE), "rw");
        try {
            file.getChannel().lock();
            return new Held(file);
        } catch (IOException | RuntimeException e) {
            file.close();
            throw e;
        }
    }

    private static JSONObject read(Context c) {
        File f = new File(c.getFilesDir(), FILE);
        if (!f.exists()) return null;
        try (FileInputStream in = new FileInputStream(f)) {
            JSONObject t = new JSONObject(text(in));
            return t.optString("refresh").isEmpty() ? null : t;
        } catch (Exception e) {
            return null;
        }
    }

    private static void write(Context c, JSONObject tokens) throws IOException {
        File tmp = new File(c.getFilesDir(), FILE + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(tokens.toString().getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        if (!tmp.renameTo(new File(c.getFilesDir(), FILE))) throw new IOException("couldn't save the sign-in");
    }

    // MARK: - HTTP

    private static final class Response {
        int code;
        String body = "";
    }

    private static Response call(String method, String path, JSONObject body, String access) throws IOException {
        HttpURLConnection h = (HttpURLConnection) new URL(API + path).openConnection();
        h.setConnectTimeout(8000);
        h.setReadTimeout(8000);
        h.setRequestMethod(method);
        h.setRequestProperty("Content-Type", "application/json");
        h.setRequestProperty("trakt-api-version", "2");
        h.setRequestProperty("trakt-api-key", clientId());
        h.setRequestProperty("User-Agent", "FreeMyTV");
        if (access != null) h.setRequestProperty("Authorization", "Bearer " + access);
        try {
            if (body != null) {
                h.setDoOutput(true);
                try (OutputStream out = h.getOutputStream()) {
                    out.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
            Response r = new Response();
            r.code = h.getResponseCode();
            InputStream in = r.code < 400 ? h.getInputStream() : h.getErrorStream();
            if (in != null) {
                try (InputStream stream = in) {
                    r.body = text(stream);
                }
            }
            return r;
        } finally {
            h.disconnect();
        }
    }

    private static String text(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
        return out.toString(StandardCharsets.UTF_8.name());
    }
}
