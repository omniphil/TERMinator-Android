package com.syncterm.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that keeps the BBS connection alive when the app is in the background.
 *
 * Android aggressively restricts network access for backgrounded apps (Doze mode, battery
 * optimization). A foreground service with a persistent notification tells Android that this
 * app is actively doing something the user cares about, preventing network restrictions.
 */
class ConnectionService : Service() {

    companion object {
        const val CHANNEL_ID = "terminator_connection"
        const val NOTIFICATION_ID = 1001

        const val ACTION_START = "com.syncterm.android.ACTION_START_CONNECTION_SERVICE"
        const val ACTION_STOP = "com.syncterm.android.ACTION_STOP_CONNECTION_SERVICE"

        const val EXTRA_CONNECTION_NAME = "connection_name"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"

        private val isRunning = AtomicBoolean(false)

        /**
         * Check if the service is currently running.
         */
        fun isServiceRunning(): Boolean = isRunning.get()

        /**
         * Start the connection service.
         */
        fun start(context: Context, connectionName: String, host: String, port: Int) {
            val intent = Intent(context, ConnectionService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONNECTION_NAME, connectionName)
                putExtra(EXTRA_HOST, host)
                putExtra(EXTRA_PORT, port)
            }
            context.startForegroundService(intent)
        }

        /**
         * Stop the connection service.
         */
        fun stop(context: Context) {
            val intent = Intent(context, ConnectionService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private var connectionName: String = ""
    private var host: String = ""
    private var port: Int = 23

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                connectionName = intent.getStringExtra(EXTRA_CONNECTION_NAME) ?: "BBS"
                host = intent.getStringExtra(EXTRA_HOST) ?: ""
                port = intent.getIntExtra(EXTRA_PORT, 23)

                startForegroundWithNotification()
                isRunning.set(true)
            }
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                isRunning.set(false)
            }
        }

        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning.set(false)
        super.onDestroy()
    }

    /**
     * Create the notification channel for Android O+.
     */
    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW  // Low importance = no sound, but visible
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }

        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(channel)
    }

    /**
     * Start the service in foreground mode with a persistent notification.
     */
    private fun startForegroundWithNotification() {
        val notification = createNotification()

        // Use the appropriate foreground service type for Android 14+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /**
     * Create the notification shown while connected.
     */
    private fun createNotification(): Notification {
        // Intent to open the terminal activity when notification is tapped
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, TerminalActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Disconnect action
        val disconnectIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ConnectionService::class.java).apply {
                action = ACTION_STOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_connected_title, connectionName))
            .setContentText(getString(R.string.notification_connected_text, host, port))
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .addAction(
                R.drawable.ic_disconnect,
                getString(R.string.disconnect),
                disconnectIntent
            )
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
