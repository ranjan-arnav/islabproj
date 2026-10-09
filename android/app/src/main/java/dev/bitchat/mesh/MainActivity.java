package dev.bitchat.mesh;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

public final class MainActivity extends Activity implements MeshNode.UiListener {
    private static final int PERMISSION_REQUEST = 40;
    private final List<DeviceItem> devices = new ArrayList<>();
    private final List<TargetItem> targets = new ArrayList<>();
    private BluetoothAdapter bluetooth;
    private MeshNode mesh;
    private boolean started;
    private TextView status, identity, linkCount;
    private EditText nickname, roomCode, message;
    private Spinner deviceSpinner, peerTypeSpinner, targetSpinner;
    private LinearLayout messageList;
    private ScrollView messageScroll;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        BluetoothManager manager = getSystemService(BluetoothManager.class);
        bluetooth = manager == null ? null : manager.getAdapter();
        setContentView(buildUi());
        if (bluetooth == null) {
            status.setText("This phone has no Bluetooth adapter");
            return;
        }
        ensurePermissionsAndStart();
    }

    private View buildUi() {
        int pad = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, dp(12), pad, dp(12));
        root.setBackgroundColor(Color.rgb(9, 11, 15));

        LinearLayout header = row();
        TextView brand = text("bitchat / ANDROID MESH", 19, Color.rgb(185, 244, 84));
        brand.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        header.addView(brand, new LinearLayout.LayoutParams(0, dp(42), 1));
        linkCount = text("0 LINKS", 10, Color.rgb(103, 213, 202));
        linkCount.setGravity(Gravity.CENTER_VERTICAL | Gravity.END);
        header.addView(linkCount, new LinearLayout.LayoutParams(dp(90), dp(42)));
        root.addView(header);

        identity = text("creating cryptographic identity...", 10, Color.rgb(123, 132, 145));
        root.addView(identity, matchWrap());

        status = text("Starting...", 11, Color.rgb(205, 212, 220));
        status.setPadding(0, dp(8), 0, dp(10));
        root.addView(status, matchWrap());

        nickname = field("Nickname", false);
        roomCode = field("Shared room code (8+ characters)", true);
        root.addView(nickname, matchWrap());
        root.addView(space(7));
        root.addView(roomCode, matchWrap());
        Button join = button("JOIN ENCRYPTED ROOM");
        join.setOnClickListener(v -> joinRoom());
        root.addView(join, marginTop(9));

        root.addView(section("PAIRED BLUETOOTH DEVICE"));
        deviceSpinner = spinner();
        root.addView(deviceSpinner, matchWrap());
        peerTypeSpinner = spinner();
        peerTypeSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                new String[]{"Android phone", "Python laptop - channel 12"}));
        root.addView(peerTypeSpinner, marginTop(6));
        LinearLayout connectionButtons = row();
        Button refresh = secondaryButton("REFRESH PAIRED");
        refresh.setOnClickListener(v -> refreshDevices());
        Button connect = button("CONNECT");
        connect.setOnClickListener(v -> connectSelected());
        connectionButtons.addView(refresh, new LinearLayout.LayoutParams(0, dp(45), 1));
        LinearLayout.LayoutParams right = new LinearLayout.LayoutParams(0, dp(45), 1); right.leftMargin = dp(7);
        connectionButtons.addView(connect, right);
        root.addView(connectionButtons, marginTop(7));

        root.addView(section("MESSAGES"));
        messageScroll = new ScrollView(this);
        messageList = new LinearLayout(this);
        messageList.setOrientation(LinearLayout.VERTICAL);
        messageScroll.addView(messageList, matchWrap());
        root.addView(messageScroll, new LinearLayout.LayoutParams(-1, 0, 1));

        targetSpinner = spinner();
        targets.add(new TargetItem(null, "# room broadcast"));
        updateTargetAdapter();
        root.addView(targetSpinner, marginTop(8));
        LinearLayout composer = row();
        message = field("Write a message", false);
        message.setMaxLines(4);
        composer.addView(message, new LinearLayout.LayoutParams(0, dp(52), 1));
        Button send = button("SEND");
        send.setOnClickListener(v -> sendMessage());
        LinearLayout.LayoutParams sendParams = new LinearLayout.LayoutParams(dp(82), dp(52)); sendParams.leftMargin = dp(7);
        composer.addView(send, sendParams);
        root.addView(composer, marginTop(7));
        return root;
    }

    private void ensurePermissionsAndStart() {
        if (Build.VERSION.SDK_INT >= 31 &&
                (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED ||
                 checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED)) {
            requestPermissions(new String[]{Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN}, PERMISSION_REQUEST);
            return;
        }
        startMesh();
    }

    @SuppressLint("MissingPermission")
    private void startMesh() {
        if (started) return;
        if (!bluetooth.isEnabled()) {
            startActivity(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE));
            status.setText("Enable Bluetooth, then return to the app");
            return;
        }
        try {
            mesh = new MeshNode(this, bluetooth, this);
            identity.setText("v1.0.6  / identity  " + mesh.fingerprint() + "  / RSA-3072");
            mesh.start();
            started = true;
            refreshDevices();
        } catch (Exception error) {
            status.setText("Startup failed: " + error.getMessage());
        }
    }

    @Override protected void onResume() {
        super.onResume();
        if (bluetooth != null && !started && hasPermissions()) startMesh();
    }

    private boolean hasPermissions() {
        return Build.VERSION.SDK_INT < 31 ||
                (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED &&
                 checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED);
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == PERMISSION_REQUEST && hasPermissions()) startMesh();
        else if (requestCode == PERMISSION_REQUEST) status.setText("Nearby devices permission is required");
    }

    private void joinRoom() {
        if (mesh == null) { toast("Bluetooth is not ready"); return; }
        try { mesh.configure(nickname.getText().toString(), roomCode.getText().toString()); roomCode.setText(""); }
        catch (Exception error) { toast(error.getMessage()); }
    }

    @SuppressLint("MissingPermission")
    private void refreshDevices() {
        if (!hasPermissions()) return;
        devices.clear();
        Set<BluetoothDevice> bonded = bluetooth.getBondedDevices();
        for (BluetoothDevice device : bonded) devices.add(new DeviceItem(device));
        devices.sort(Comparator.comparing(DeviceItem::toString));
        deviceSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, devices));
        if (devices.isEmpty()) status.setText("Pair a phone or laptop in Android Bluetooth settings first");
    }

    private void connectSelected() {
        if (mesh == null || deviceSpinner.getSelectedItem() == null) { toast("Choose a paired device"); return; }
        DeviceItem item = (DeviceItem) deviceSpinner.getSelectedItem();
        boolean laptop = peerTypeSpinner.getSelectedItemPosition() == 1;
        status.setText("Connecting to " + item + "...");
        mesh.connect(item.device, laptop);
    }

    private void sendMessage() {
        if (mesh == null) return;
        TargetItem selected = (TargetItem) targetSpinner.getSelectedItem();
        try {
            mesh.send(message.getText().toString(), selected == null ? null : selected.id);
            message.setText("");
        } catch (Exception error) { toast(error.getMessage()); }
    }

    @Override public void onStatus(String value) { runOnUiThread(() -> status.setText(value)); }
    @Override public void onLinks(int count) { runOnUiThread(() -> linkCount.setText(count + " LINK" + (count == 1 ? "" : "S"))); }
    @Override public void onParticipants(List<MeshNode.Participant> people) {
        runOnUiThread(() -> {
            String selectedId = targetSpinner.getSelectedItem() instanceof TargetItem ? ((TargetItem) targetSpinner.getSelectedItem()).id : null;
            targets.clear(); targets.add(new TargetItem(null, "# room broadcast"));
            for (MeshNode.Participant person : people) targets.add(new TargetItem(person.id, person.toString()));
            updateTargetAdapter();
            if (selectedId != null) for (int i = 0; i < targets.size(); i++) if (selectedId.equals(targets.get(i).id)) targetSpinner.setSelection(i);
            if (!people.isEmpty()) status.setText(people.size() + " private recipient" +
                    (people.size() == 1 ? "" : "s") + " available");
        });
    }

    @Override public void onMessage(MeshNode.ChatMessage item) {
        runOnUiThread(() -> {
            LinearLayout card = new LinearLayout(this); card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(dp(10), dp(8), dp(10), dp(8)); card.setBackgroundColor(Color.rgb(17, 21, 27));
            String privacy = item.privateMessage ? (item.local ? "  PRIVATE TO " + item.recipient : "  PRIVATE TO YOU") : "  ROOM";
            TextView heading = text(item.nickname + privacy + "  / " + (item.hops == 0 ? "local" : item.hops + " hop"), 10,
                    item.privateMessage ? Color.rgb(103, 213, 202) : Color.rgb(185, 244, 84));
            TextView body = text(item.text, 14, Color.rgb(237, 241, 245)); body.setPadding(0, dp(6), 0, 0);
            card.addView(heading); card.addView(body);
            LinearLayout.LayoutParams params = marginTop(5); messageList.addView(card, params);
            messageScroll.post(() -> messageScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void updateTargetAdapter() {
        targetSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, targets));
    }

    private LinearLayout row() { LinearLayout value = new LinearLayout(this); value.setOrientation(LinearLayout.HORIZONTAL); return value; }
    private TextView text(String value, int size, int color) { TextView view = new TextView(this); view.setText(value); view.setTextSize(size); view.setTextColor(color); return view; }
    private TextView section(String value) { TextView view = text(value, 10, Color.rgb(123,132,145)); view.setPadding(0, dp(14), 0, dp(6)); return view; }
    private EditText field(String hint, boolean password) {
        EditText view = new EditText(this); view.setHint(hint); view.setHintTextColor(Color.rgb(84,92,101)); view.setTextColor(Color.WHITE);
        view.setTextSize(12); view.setSingleLine(!hint.startsWith("Write")); view.setBackgroundResource(dev.bitchat.mesh.R.drawable.field_bg);
        if (password) view.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        return view;
    }
    private Spinner spinner() { Spinner value = new Spinner(this); value.setBackgroundResource(dev.bitchat.mesh.R.drawable.field_bg); return value; }
    private Button button(String value) { Button view = new Button(this); view.setText(value); view.setTextColor(Color.rgb(9,11,15)); view.setTextSize(10); view.setBackgroundResource(dev.bitchat.mesh.R.drawable.button_bg); return view; }
    private Button secondaryButton(String value) { Button view = button(value); view.setTextColor(Color.LTGRAY); view.setBackgroundResource(dev.bitchat.mesh.R.drawable.field_bg); return view; }
    private View space(int height) { View view = new View(this); view.setLayoutParams(new LinearLayout.LayoutParams(1, dp(height))); return view; }
    private LinearLayout.LayoutParams matchWrap() { return new LinearLayout.LayoutParams(-1, -2); }
    private LinearLayout.LayoutParams marginTop(int top) { LinearLayout.LayoutParams value = matchWrap(); value.topMargin = dp(top); return value; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private void toast(String value) { Toast.makeText(this, value, Toast.LENGTH_LONG).show(); }

    @SuppressLint("MissingPermission")
    private static final class DeviceItem {
        final BluetoothDevice device;
        DeviceItem(BluetoothDevice device) { this.device = device; }
        @Override public String toString() { String name = device.getName(); return (name == null ? "Unknown" : name) + "  " + device.getAddress(); }
    }
    private static final class TargetItem {
        final String id, label;
        TargetItem(String id, String label) { this.id = id; this.label = label; }
        @Override public String toString() { return label; }
    }
}
