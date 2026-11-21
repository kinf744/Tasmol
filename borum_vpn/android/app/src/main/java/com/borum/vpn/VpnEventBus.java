package com.borum.vpn;

import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.WeakHashMap;

/**
 * Source centrale d'événements du journal BORUM VPN.
 *
 * Génération (TasVpnService, moteurs, fragments) -> classement ->
 * stockage temporaire (mémoire, taille limitée) -> diffusion vers l'UI.
 * Thread-safe. Ne ralentit pas les connexions VPN (ajout O(1), notification
 * postée sur le thread principal).
 */
public final class VpnEventBus {
    private static final int MAX_EVENTS = 500;

    private static volatile VpnEventBus sInstance;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final LinkedList<VpnEvent> events = new LinkedList<>();
    private final WeakHashMap<Object, Observer> observers = new WeakHashMap<>();

    private boolean frozen = false;
    private String filter = "tout"; // tout, problemes, connexion, application

    private VpnEventBus() {
    }

    public static VpnEventBus get() {
        if (sInstance == null) {
            synchronized (VpnEventBus.class) {
                if (sInstance == null) {
                    sInstance = new VpnEventBus();
                }
            }
        }
        return sInstance;
    }

    public synchronized void add(String level, String component, String message) {
        if (TextUtils.isEmpty(message)) {
            return;
        }
        VpnEvent ev = new VpnEvent(System.currentTimeMillis(), level, component, message);
        events.addLast(ev);
        while (events.size() > MAX_EVENTS) {
            events.removeFirst();
        }
        if (!frozen) {
            notifyObservers();
        }
    }

    /** Ajoute un événement avec composant "app". */
    public void addApp(String level, String message) {
        add(level, "app", message);
    }

    /** Ajoute un événement de connexion/moteur. */
    public void addConnection(String level, String component, String message) {
        add(level, component, message);
    }

    /**
     * Ingère une ligne brute du journal (format "[niveau] [composant] msg" ou
     * "[niveau] msg" ou texte libre) et la transforme en événement structuré.
     */
    public synchronized void ingest(String raw) {
        if (raw == null) {
            return;
        }
        String l = raw.trim();
        if (l.isEmpty()) {
            return;
        }
        java.util.regex.Matcher m =
                java.util.regex.Pattern.compile("^\\[([^\\]]+)\\](?:\\[([^\\]]+)\\])?\\s?(.*)$",
                        java.util.regex.Pattern.DOTALL).matcher(l);
        if (m.matches()) {
            add(m.group(1), m.group(2), m.group(3));
        } else {
            add("info", "app", l);
        }
    }

    public synchronized List<VpnEvent> getEventsFiltered() {
        List<VpnEvent> out = new ArrayList<>(events);
        Collections.reverse(out);
        if (filter == null || "tout".equals(filter)) {
            return out;
        }
        List<VpnEvent> filtered = new ArrayList<>();
        for (VpnEvent ev : out) {
            if (ev.matchesFilter(filter)) {
                filtered.add(ev);
            }
        }
        return filtered;
    }

    public synchronized int count(String f) {
        int c = 0;
        for (VpnEvent ev : events) {
            if (ev.matchesFilter(f)) {
                c++;
            }
        }
        return c;
    }

    public synchronized int total() {
        return events.size();
    }

    public synchronized String getFilter() {
        return filter;
    }

    public synchronized void setFilter(String filter) {
        this.filter = filter == null ? "tout" : filter;
        notifyObservers();
    }

    public synchronized boolean isFrozen() {
        return frozen;
    }

    public synchronized void setFrozen(boolean frozen) {
        this.frozen = frozen;
        if (!frozen) {
            notifyObservers();
        }
    }

    /** Vide l'affichage (en mémoire) sans arrêter le VPN ni toucher aux profils. */
    public synchronized void clear() {
        events.clear();
        notifyObservers();
    }

    /** Rapport texte partageable, sans données sensibles. */
    public synchronized String shareText() {
        StringBuilder sb = new StringBuilder();
        sb.append("BORUM VPN - Journal d'activité\n");
        sb.append("Date : ").append(java.text.SimpleDateFormat.getDateTimeInstance()
                .format(new java.util.Date())).append("\n");
        sb.append("Événements : ").append(events.size()).append("\n");
        sb.append("----------------------------------------\n");
        List<VpnEvent> list = new ArrayList<>(events);
        Collections.reverse(list);
        java.text.SimpleDateFormat tf = new java.text.SimpleDateFormat("HH:mm:ss");
        for (VpnEvent ev : list) {
            sb.append(tf.format(new java.util.Date(ev.timestamp)))
                    .append(" [").append(ev.level).append("] ")
                    .append(ev.component).append(": ").append(ev.message).append("\n");
        }
        return sb.toString();
    }

    // -------- observers --------

    public interface Observer {
        void onEventsChanged(List<VpnEvent> events);
    }

    public synchronized void register(Object key, Observer observer) {
        observers.put(key, observer);
        // envoi immédiat de l'état courant
        if (observer != null) {
            mainHandler.post(() -> observer.onEventsChanged(getEventsFiltered()));
        }
    }

    public synchronized void unregister(Object key) {
        observers.remove(key);
    }

    private synchronized void notifyObservers() {
        final List<VpnEvent> current = getEventsFiltered();
        for (Observer obs : observers.values()) {
            final Observer o = obs;
            if (o != null) {
                mainHandler.post(() -> o.onEventsChanged(current));
            }
        }
    }

    // seed depuis un journal texte existant (ex: BinaryManager) au premier lancement
    public synchronized void seedFromLines(Iterable<String> lines) {
        int added = 0;
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String l = line.trim();
            if (l.isEmpty()) {
                continue;
            }
            // format : [level] [component] msg  ou  [level] msg
            java.util.regex.Matcher m =
                    java.util.regex.Pattern.compile("^\\[([^\\]]+)\\](?:\\[([^\\]]+)\\])?\\s?(.*)$",
                            java.util.regex.Pattern.DOTALL).matcher(l);
            if (m.matches()) {
                add(m.group(1), m.group(2), m.group(3));
            } else {
                add("info", "app", l);
            }
            if (++added >= MAX_EVENTS) {
                break;
            }
        }
        if (!frozen) {
            notifyObservers();
        }
    }
}
