package com.syncterm.android

import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.DialogFragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Retro DOS-style dialog fragment that displays file transfer progress.
 * Styled to look like classic ZMODEM transfer screens.
 */
class TransferDialogFragment : DialogFragment() {

    private var transferManager: TransferManager? = null
    private var onDismissListener: (() -> Unit)? = null
    private var bellManager: BellManager? = null
    private var bellPlayed = false
    private var autoCloseJob: kotlinx.coroutines.Job? = null

    companion object {
        const val TAG = "TransferDialog"
        private const val PROGRESS_WIDTH = 25  // Number of characters in progress bar
        private const val FILLED_CHAR = '█'    // Full block
        private const val EMPTY_CHAR = '░'     // Light shade
        private const val AUTO_CLOSE_SECONDS = 5  // Auto-close countdown

        fun newInstance(): TransferDialogFragment {
            return TransferDialogFragment()
        }

        /**
         * Build a retro text-based progress bar string.
         */
        fun buildProgressBar(percent: Int): String {
            val filled = (percent * PROGRESS_WIDTH / 100).coerceIn(0, PROGRESS_WIDTH)
            val empty = PROGRESS_WIDTH - filled
            return "[${FILLED_CHAR.toString().repeat(filled)}${EMPTY_CHAR.toString().repeat(empty)}]"
        }
    }

    // Colors from app theme (initialized in onViewCreated)
    private var colorAccent = 0
    private var colorPrimary = 0
    private var colorRed = 0
    private var colorYellow = 0

    // Views
    private lateinit var titleText: TextView
    private lateinit var fileNameText: TextView
    private lateinit var progressBarText: TextView  // Text-based progress bar
    private lateinit var progressText: TextView
    private lateinit var progressPercent: TextView
    private lateinit var speedText: TextView
    private lateinit var statusText: TextView
    private lateinit var cancelButton: TextView
    private lateinit var closeButton: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setStyle(STYLE_NO_FRAME, R.style.Theme_SyncTERM_Dialog_Retro)
        isCancelable = false
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.dialog_transfer, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Initialize colors from resources
        colorAccent = resources.getColor(R.color.accent, null)
        colorPrimary = resources.getColor(R.color.primary, null)
        colorRed = resources.getColor(R.color.term_light_red, null)
        colorYellow = resources.getColor(R.color.term_yellow, null)

        // Initialize bell manager
        bellManager = BellManager(requireContext())

        // Initialize views
        titleText = view.findViewById(R.id.transferTitle)
        fileNameText = view.findViewById(R.id.fileName)
        progressBarText = view.findViewById(R.id.progressBar)
        progressText = view.findViewById(R.id.progressText)
        progressPercent = view.findViewById(R.id.progressPercent)
        speedText = view.findViewById(R.id.speedText)
        statusText = view.findViewById(R.id.statusText)
        cancelButton = view.findViewById(R.id.cancelButton)
        closeButton = view.findViewById(R.id.closeButton)

        // Set up button listeners
        cancelButton.setOnClickListener {
            // Check if native transfer has already completed - if so, just dismiss
            val nativeState = NativeBridge.nativeGetTransferState()
            if (nativeState >= 3) { // COMPLETE, ERROR, or CANCELLED
                android.util.Log.i(TAG, "Cancel clicked but native state=$nativeState, dismissing dialog")
                autoCloseJob?.cancel()
                dismiss()
                onDismissListener?.invoke()
            } else {
                transferManager?.cancelTransfer()
            }
        }

        closeButton.setOnClickListener {
            autoCloseJob?.cancel()
            dismiss()
            onDismissListener?.invoke()
        }

        // Start observing transfer state
        observeTransferState()
    }

    override fun onStart() {
        super.onStart()
        // Make dialog transparent background and wrap content
        dialog?.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }
    }

    override fun onDestroyView() {
        autoCloseJob?.cancel()
        super.onDestroyView()
    }

    /**
     * Set the transfer manager to observe.
     */
    fun setTransferManager(manager: TransferManager) {
        this.transferManager = manager
    }

    /**
     * Set callback for when dialog is dismissed.
     */
    fun setOnDismissListener(listener: () -> Unit) {
        this.onDismissListener = listener
    }

    /**
     * Observe transfer state and update UI.
     */
    private fun observeTransferState() {
        val manager = transferManager
        if (manager == null) {
            android.util.Log.w(TAG, "TransferManager not set - call setTransferManager() before showing dialog")
            // Show error state in UI
            statusText.text = "ERROR: No transfer manager"
            statusText.setTextColor(colorRed)
            cancelButton.visibility = View.GONE
            closeButton.visibility = View.VISIBLE
            return
        }

        viewLifecycleOwner.lifecycleScope.launch {
            manager.transferState.collectLatest { info ->
                updateUI(info)
            }
        }

        // Fallback: periodically check native state directly in case StateFlow updates are missed
        viewLifecycleOwner.lifecycleScope.launch {
            while (true) {
                delay(500)
                checkNativeStateDirectly()
            }
        }
    }

    /**
     * Check native transfer state directly as a fallback.
     */
    private fun checkNativeStateDirectly() {
        val currentState = transferManager?.transferState?.value?.state ?: return

        if (currentState != TransferState.SENDING && currentState != TransferState.RECEIVING) {
            return
        }

        val nativeState = NativeBridge.nativeGetTransferState()

        when (nativeState) {
            3 -> { // TRANSFER_COMPLETE
                android.util.Log.i(TAG, "Native reports COMPLETE, updating dialog")
                val info = transferManager?.transferState?.value?.copy(state = TransferState.COMPLETE)
                if (info != null) updateUI(info)
            }
            4 -> { // TRANSFER_ERROR
                android.util.Log.i(TAG, "Native reports ERROR, updating dialog")
                val error = NativeBridge.nativeGetTransferError() ?: "Transfer failed"
                val info = transferManager?.transferState?.value?.copy(
                    state = TransferState.ERROR,
                    errorMessage = error
                )
                if (info != null) updateUI(info)
            }
            5 -> { // TRANSFER_CANCELLED
                android.util.Log.i(TAG, "Native reports CANCELLED, updating dialog")
                val info = transferManager?.transferState?.value?.copy(state = TransferState.CANCELLED)
                if (info != null) updateUI(info)
            }
        }
    }

    /**
     * Play bell and start auto-close countdown when transfer ends.
     */
    private fun onTransferEnded(statusMessage: String, statusColor: Int) {
        // Play bell once
        if (!bellPlayed) {
            bellPlayed = true
            bellManager?.playBell()
        }

        // Cancel any existing auto-close job
        autoCloseJob?.cancel()

        // Start auto-close countdown
        autoCloseJob = viewLifecycleOwner.lifecycleScope.launch {
            for (secondsLeft in AUTO_CLOSE_SECONDS downTo 1) {
                statusText.text = "$statusMessage (closing in ${secondsLeft}s)"
                statusText.setTextColor(statusColor)
                delay(1000)
            }
            // Auto-close after countdown
            if (isAdded && !isStateSaved) {
                dismiss()
                onDismissListener?.invoke()
            }
        }
    }

    /**
     * Update UI with transfer info using retro DOS styling.
     */
    private fun updateUI(info: TransferInfo) {
        // Update title based on direction (DOS style - all caps)
        titleText.text = when (info.direction) {
            TransferDirection.SEND -> " ZMODEM Send "
            TransferDirection.RECEIVE -> " ZMODEM Recv "
            TransferDirection.NONE -> " ZMODEM "
        }

        // Update file name
        fileNameText.text = info.fileName ?: "--"

        // Update progress with text-based bar
        progressBarText.text = buildProgressBar(info.progressPercent)
        progressPercent.text = "${info.progressPercent}%"

        // Retro-style progress text (Bytes: X / Y format)
        progressText.text = "Bytes: ${info.bytesTransferred} / ${info.totalBytes}"

        // Speed in cps (characters per second - classic BBS terminology)
        speedText.text = "Speed: ${info.bytesPerSecond} cps"

        // Update state-specific UI with app theme colors
        when (info.state) {
            TransferState.IDLE -> {
                statusText.visibility = View.VISIBLE
                statusText.text = "Waiting for remote..."
                statusText.setTextColor(colorYellow)
                cancelButton.visibility = View.VISIBLE
                closeButton.visibility = View.GONE
            }
            TransferState.RECEIVING, TransferState.SENDING -> {
                statusText.visibility = View.VISIBLE
                statusText.text = "Transferring..."
                statusText.setTextColor(colorAccent)
                cancelButton.visibility = View.VISIBLE
                closeButton.visibility = View.GONE
            }
            TransferState.COMPLETE -> {
                statusText.visibility = View.VISIBLE
                cancelButton.visibility = View.GONE
                closeButton.visibility = View.VISIBLE
                progressBarText.text = buildProgressBar(100)
                progressPercent.text = "100%"
                onTransferEnded("Transfer OK!", colorAccent)
            }
            TransferState.ERROR -> {
                statusText.visibility = View.VISIBLE
                val errorMsg = info.errorMessage ?: "Unknown error"
                cancelButton.visibility = View.GONE
                closeButton.visibility = View.VISIBLE
                onTransferEnded("ERROR: $errorMsg", colorRed)
            }
            TransferState.CANCELLED -> {
                statusText.visibility = View.VISIBLE
                cancelButton.visibility = View.GONE
                closeButton.visibility = View.VISIBLE
                onTransferEnded("Transfer ABORTED", colorYellow)
            }
        }
    }
}
