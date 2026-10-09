package dev.bitchat.mesh;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

final class BluetoothTransport {
    static final UUID SERVICE_UUID = UUID.fromString("7c2f4f4e-7c4d-4b8a-9c2b-16c8a43bb512");
    private final BluetoothAdapter adapter;
    private final Listener listener;
    private final List<Link> links = new CopyOnWriteArrayList<>();
    private volatile BluetoothServerSocket server;

    interface Listener {
        void onPacket(JSONObject packet, Link ingress);
        void onStatus(String text);
        void onLinksChanged(int count);
    }

    BluetoothTransport(BluetoothAdapter adapter, Listener listener) {
        this.adapter = adapter;
        this.listener = listener;
    }

    @SuppressLint("MissingPermission")
    void start() {
        new Thread(() -> {
            try {
                server = adapter.listenUsingInsecureRfcommWithServiceRecord("Bitchat Mesh", SERVICE_UUID);
                listener.onStatus("Bluetooth relay listening");
                while (!Thread.currentThread().isInterrupted()) add(server.accept());
            } catch (Exception error) {
                listener.onStatus("Bluetooth listener stopped: " + error.getMessage());
            }
        }, "rfcomm-server").start();
    }

    @SuppressLint("MissingPermission")
    void connect(BluetoothDevice device, boolean laptopChannel) {
        new Thread(() -> {
            BluetoothSocket socket = null;
            try {
                adapter.cancelDiscovery();
                if (laptopChannel) {
                    socket = connectLaptopChannel(device);
                } else {
                    socket = connectAndroidService(device);
                }
                add(socket);
                listener.onStatus("Connected to " + safeName(device));
            } catch (Exception error) {
                if (socket != null) try { socket.close(); } catch (Exception ignored) {}
                listener.onStatus("Connection failed: " + friendlyError(error));
            }
        }, "rfcomm-connect").start();
    }

    /**
     * The Python Windows listener exposes RFCOMM channel 12 but cannot publish an
     * Android-style SDP UUID. Different Android vendors permit either the insecure
     * or secure raw-channel socket, so try both before reporting failure.
     */
    @SuppressLint("MissingPermission")
    private BluetoothSocket connectLaptopChannel(BluetoothDevice device) throws Exception {
        List<String> failures = new ArrayList<>();
        String[] methods = {"createInsecureRfcommSocket", "createRfcommSocket"};
        for (String methodName : methods) {
            BluetoothSocket candidate = null;
            try {
                listener.onStatus("Trying laptop RFCOMM channel 12 (" +
                        (methodName.contains("Insecure") ? "insecure" : "secure") + ")...");
                Method method = BluetoothDevice.class.getMethod(methodName, int.class);
                candidate = (BluetoothSocket) method.invoke(device, 12);
                candidate.connect();
                return candidate;
            } catch (Exception error) {
                failures.add(methodName + ": " + friendlyError(error));
                if (candidate != null) try { candidate.close(); } catch (Exception ignored) {}
            }
        }
        throw new Exception(String.join(" | ", failures));
    }

    @SuppressLint("MissingPermission")
    private BluetoothSocket connectAndroidService(BluetoothDevice device) throws Exception {
        BluetoothSocket socket = device.createInsecureRfcommSocketToServiceRecord(SERVICE_UUID);
        try {
            socket.connect();
            return socket;
        } catch (Exception error) {
            try { socket.close(); } catch (Exception ignored) {}
            throw error;
        }
    }

    private static String friendlyError(Throwable error) {
        Throwable current = error;
        while (current instanceof InvocationTargetException &&
                ((InvocationTargetException) current).getTargetException() != null) {
            current = ((InvocationTargetException) current).getTargetException();
        }
        while (current.getCause() != null && current.getCause() != current) current = current.getCause();
        String message = current.getMessage();
        return current.getClass().getSimpleName() +
                (message == null || message.trim().isEmpty() ? "" : ": " + message.trim());
    }

    void broadcast(JSONObject packet, Link exclude) {
        String frame = packet.toString() + "\n";
        for (Link link : links) {
            if (link != exclude) link.send(frame);
        }
    }

    int count() { return links.size(); }

    private void add(BluetoothSocket socket) throws Exception {
        Link link = new Link(socket);
        links.add(link);
        listener.onLinksChanged(links.size());
        link.start();
    }

    @SuppressLint("MissingPermission")
    private static String safeName(BluetoothDevice device) {
        try { return device.getName() + " (" + device.getAddress() + ")"; }
        catch (SecurityException ignored) { return device.getAddress(); }
    }

    final class Link {
        final BluetoothSocket socket;
        final BufferedWriter writer;

        Link(BluetoothSocket socket) throws Exception {
            this.socket = socket;
            this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        }

        void start() {
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.length() <= 65536) listener.onPacket(new JSONObject(line), this);
                    }
                } catch (Exception ignored) {
                } finally {
                    links.remove(this);
                    try { socket.close(); } catch (Exception ignored) {}
                    listener.onLinksChanged(links.size());
                }
            }, "rfcomm-link").start();
        }

        synchronized void send(String frame) {
            try { writer.write(frame); writer.flush(); }
            catch (Exception error) { try { socket.close(); } catch (Exception ignored) {} }
        }
    }
}
