package com.syncterm.android

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.text.InputType
import android.util.AttributeSet
import android.util.Log
import android.util.LruCache
import android.view.GestureDetector
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import kotlin.math.max
import kotlin.math.min

/**
 * Custom View that renders the terminal screen using the native screen buffer.
 */
class TerminalView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    companion object {
        private const val TAG = "TerminalView"
        private const val MIN_ZOOM = 0.5f
        private const val MAX_ZOOM = 3.0f
    }

    // Paint objects
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        textAlign = Paint.Align.LEFT
    }

    private val bgPaint = Paint().apply {
        style = Paint.Style.FILL
    }

    private val cursorPaint = Paint().apply {
        style = Paint.Style.FILL
    }

    // Cell dimensions
    private var cellWidth = 0f
    private var cellHeight = 0f
    private var textBaseline = 0f

    // Zoom level (1.0 = fit to screen)
    private var zoomLevel = 1.0f

    // Base font size (calculated to fit 80x25 on screen)
    private var baseFontSize = 24f

    // Terminal dimensions - fixed for BBS
    private var termWidth = 80
    private var termHeight = 25

    // DOS 16-color palette (default CGA/VGA colors)
    private var colorPalette = intArrayOf(
        0xFF000000.toInt(), // 0: Black
        0xFF0000AA.toInt(), // 1: Blue
        0xFF00AA00.toInt(), // 2: Green
        0xFF00AAAA.toInt(), // 3: Cyan
        0xFFAA0000.toInt(), // 4: Red
        0xFFAA00AA.toInt(), // 5: Magenta
        0xFFAA5500.toInt(), // 6: Brown
        0xFFAAAAAA.toInt(), // 7: Light Gray
        0xFF555555.toInt(), // 8: Dark Gray
        0xFF5555FF.toInt(), // 9: Light Blue
        0xFF55FF55.toInt(), // 10: Light Green
        0xFF55FFFF.toInt(), // 11: Light Cyan
        0xFFFF5555.toInt(), // 12: Light Red
        0xFFFF55FF.toInt(), // 13: Light Magenta
        0xFFFFFF55.toInt(), // 14: Yellow
        0xFFFFFFFF.toInt()  // 15: White
    )

    // Cursor state
    private var cursorX = 1
    private var cursorY = 1
    private var cursorVisible = true
    private var cursorBlinkOn = true
    private var lastCursorBlink = 0L
    private val cursorBlinkInterval = 500L // ms
    private var showCursor = false  // User preference: cursor hidden by default

    // Screen buffer (cached from native)
    @Volatile
    private var screenBuffer: IntArray? = null

    // Font type for character mapping
    enum class FontType { CP437, AMIGA }
    private var currentFontType = FontType.CP437

    // Bitmap font rendering
    private var fontBitmap: ByteArray? = null
    private var fontWidth = 8
    private var fontHeight = 16
    private var useBitmapFont = true  // Use bitmap font for accurate CP437 rendering

    // Glyph cache: key = (charCode << 8) | (fgIndex << 4) | bgIndex
    // Caches pre-rendered character bitmaps to avoid recreating them every frame
    // Custom LruCache that recycles evicted bitmaps to prevent memory leaks
    private val glyphCache = object : LruCache<Int, Bitmap>(1024) {
        override fun sizeOf(key: Int, value: Bitmap): Int {
            // Size in kilobytes
            return value.byteCount / 1024
        }

        override fun entryRemoved(evicted: Boolean, key: Int, oldValue: Bitmap, newValue: Bitmap?) {
            // Recycle the bitmap when it's evicted from cache
            if (evicted && !oldValue.isRecycled) {
                oldValue.recycle()
            }
        }
    }

    // Track previous frame buffer to avoid unnecessary redraws
    @Volatile
    private var previousBuffer: IntArray? = null
    private var forceFullRedraw = true  // Force full redraw on first frame or after changes

    // Dirty region tracking for partial redraws (screen coordinates)
    private var dirtyMinX = 0
    private var dirtyMinY = 0
    private var dirtyMaxX = 0
    private var dirtyMaxY = 0
    private var hasDirtyRegion = false

    // Paint for pixel-perfect bitmap scaling (no filtering)
    private val bitmapPaint = Paint().apply {
        isFilterBitmap = false  // Nearest-neighbor scaling
        isAntiAlias = false
    }

    // Last known good dimensions for when keyboard shrinks the view
    private var lastGoodWidth = 0
    private var lastGoodHeight = 0
    private var hasValidDimensions = false

    // Flag to control cursor animation (should be false when activity is paused)
    private var isAnimating = true

    // Flag to prevent log spam when font loading fails
    private var hasLoggedFontWarning = false

    // Callback for size changes
    var onTerminalSizeChanged: ((width: Int, height: Int) -> Unit)? = null

    // Callback for URL taps
    var onUrlTapped: ((String) -> Unit)? = null

    // URL detection
    data class UrlRegion(
        val url: String,
        val startRow: Int,
        val startCol: Int,
        val endRow: Int,
        val endCol: Int
    )
    private var detectedUrls = listOf<UrlRegion>()

    // URL pattern matching - matches http://, https://, ftp://, www.
    private val urlPattern = Regex(
        """(https?://|ftp://|www\.)[^\s<>\[\](){}'"`,;]+[^\s<>\[\](){}'"`,;.!?]""",
        RegexOption.IGNORE_CASE
    )

    // Gesture detector for tap handling and scrolling
    private val gestureDetector = GestureDetector(context, object : GestureDetector.SimpleOnGestureListener() {
        override fun onSingleTapUp(e: MotionEvent): Boolean {
            return handleTap(e.x, e.y)
        }

        override fun onLongPress(e: MotionEvent) {
            // Long press still shows keyboard (existing behavior)
            performClick()
        }

        override fun onScroll(
            e1: MotionEvent?,
            e2: MotionEvent,
            distanceX: Float,
            distanceY: Float
        ): Boolean {
            // Only allow panning when zoomed in beyond screen bounds
            if (zoomLevel > 1.0f) {
                panOffsetX -= distanceX
                panOffsetY -= distanceY
                clampPanOffset()
                invalidate()
                return true
            }
            return false
        }

        override fun onFling(
            e1: MotionEvent?,
            e2: MotionEvent,
            velocityX: Float,
            velocityY: Float
        ): Boolean {
            // Fling is not used for scrollback - we use onScroll with two fingers
            return false
        }

        override fun onDoubleTap(e: MotionEvent): Boolean {
            // Double tap to reset zoom to fit-to-screen and clear pan
            if (zoomLevel != 1.0f || panOffsetX != 0f || panOffsetY != 0f) {
                zoomLevel = 1.0f
                panOffsetX = 0f
                panOffsetY = 0f
                calculateCellSize(notifySizeChange = false)
                clampPanOffset()
                invalidate()
                return true
            }
            return false
        }
    })

    // Scale gesture detector for pinch-to-zoom
    private val scaleGestureDetector = ScaleGestureDetector(context, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        private var lastFocusX = 0f
        private var lastFocusY = 0f

        override fun onScaleBegin(detector: ScaleGestureDetector): Boolean {
            lastFocusX = detector.focusX
            lastFocusY = detector.focusY
            return true
        }

        override fun onScale(detector: ScaleGestureDetector): Boolean {
            val scaleFactor = detector.scaleFactor
            val oldZoom = zoomLevel

            // Apply scale
            zoomLevel = (zoomLevel * scaleFactor).coerceIn(MIN_ZOOM, MAX_ZOOM)

            if (zoomLevel != oldZoom) {
                // Adjust pan to keep focus point stationary
                val zoomChange = zoomLevel / oldZoom
                panOffsetX = detector.focusX - (detector.focusX - panOffsetX) * zoomChange
                panOffsetY = detector.focusY - (detector.focusY - panOffsetY) * zoomChange

                calculateCellSize(notifySizeChange = false)
                clampPanOffset()
                invalidate()
            }

            return true
        }

        override fun onScaleEnd(detector: ScaleGestureDetector) {
            // Reset pan if zoomed out to fit screen
            if (zoomLevel <= 1.0f) {
                panOffsetX = 0f
                panOffsetY = 0f
            }
            clampPanOffset()
        }
    })

    // Pan offset for scrolling when zoomed in
    private var panOffsetX = 0f
    private var panOffsetY = 0f

    // Track if we're in a scaling gesture (to ignore single-finger events during pinch)
    private var isScaling = false

    // Scrollback buffer navigation
    private var scrollbackOffset = 0  // 0 = live view, >0 = lines scrolled back
    private var scrollbackAvailable = 0  // Total scrollback lines available
    private var scrollbackCols = 0  // Columns in scrollback buffer

    // Callback for scrollback state changes (for showing/hiding indicators)
    var onScrollbackStateChanged: ((isScrolledBack: Boolean, linesBack: Int, totalLines: Int) -> Unit)? = null

    init {
        // Load palette from native if available
        updatePalette()
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        calculateCellSize()
    }

    /**
     * Calculate optimal cell size based on view dimensions and zoom level.
     * Terminal size is fixed at 80x25 for BBS compatibility.
     */
    private fun calculateCellSize(notifySizeChange: Boolean = true) {
        // If view has no size yet, skip
        if (width <= 0 || height <= 0) return

        // Minimum height needed to consider this a "good" size (not keyboard-shrunk)
        val minRequiredHeight = 200

        // If view is large enough, save as last good dimensions
        if (height >= minRequiredHeight) {
            lastGoodWidth = width
            lastGoodHeight = height
            hasValidDimensions = true
        }

        // If view is too small (keyboard open) and we have saved dimensions, use those
        val calcWidth: Int
        val calcHeight: Int
        if (height < minRequiredHeight && hasValidDimensions) {
            calcWidth = lastGoodWidth
            calcHeight = lastGoodHeight
        } else if (height < minRequiredHeight && !hasValidDimensions) {
            // First layout is with keyboard open and we have no saved dimensions
            // Skip calculation, will be done when keyboard closes
            return
        } else {
            calcWidth = width
            calcHeight = height
        }

        // Start with a reference font size
        val refFontSize = 24f
        textPaint.textSize = refFontSize

        // Measure a character at reference size
        val charWidth = textPaint.measureText("M")
        val charHeight = textPaint.fontMetrics.let { it.descent - it.ascent }

        // Calculate the base font size that fits 80x25 on screen
        val scaleX = calcWidth.toFloat() / (termWidth * charWidth)
        val scaleY = calcHeight.toFloat() / (termHeight * charHeight)
        val scale = min(scaleX, scaleY)
        baseFontSize = refFontSize * scale

        // Apply zoom level to the base font size
        val fontSize = baseFontSize * zoomLevel
        textPaint.textSize = fontSize

        // Recalculate cell dimensions
        cellWidth = textPaint.measureText("M")
        val metrics = textPaint.fontMetrics
        cellHeight = metrics.descent - metrics.ascent
        textBaseline = -metrics.ascent

        // Only notify size change when not just zooming
        if (notifySizeChange) {
            onTerminalSizeChanged?.invoke(termWidth, termHeight)
        }
    }

    /**
     * Reset zoom to fit screen and clear pan offset.
     */
    fun resetZoom() {
        zoomLevel = 1.0f
        panOffsetX = 0f
        panOffsetY = 0f
        calculateCellSize(notifySizeChange = false)  // Don't notify - terminal size unchanged
        invalidate()
    }

    /**
     * Clamp pan offset to prevent scrolling beyond content bounds.
     */
    private fun clampPanOffset() {
        // Calculate content size at current zoom
        val contentWidth = termWidth * cellWidth
        val contentHeight = termHeight * cellHeight

        // Calculate view dimensions (use saved dimensions if keyboard is open)
        val viewWidth = if (hasValidDimensions && height < 200) lastGoodWidth.toFloat() else width.toFloat()
        val viewHeight = if (hasValidDimensions && height < 200) lastGoodHeight.toFloat() else height.toFloat()

        if (viewWidth <= 0 || viewHeight <= 0) return

        // If content fits in view, no panning needed
        if (contentWidth <= viewWidth) {
            panOffsetX = 0f
        } else {
            // Allow panning but clamp to content bounds
            val maxPanX = 0f
            val minPanX = viewWidth - contentWidth
            panOffsetX = panOffsetX.coerceIn(minPanX, maxPanX)
        }

        if (contentHeight <= viewHeight) {
            panOffsetY = 0f
        } else {
            val maxPanY = 0f
            val minPanY = viewHeight - contentHeight
            panOffsetY = panOffsetY.coerceIn(minPanY, maxPanY)
        }
    }

    /**
     * Reset saved dimensions (call on configuration change like fold/unfold).
     * This forces recalculation with new screen dimensions.
     */
    fun resetSavedDimensions() {
        hasValidDimensions = false
        lastGoodWidth = 0
        lastGoodHeight = 0
    }

    /**
     * Get current zoom level.
     */
    fun getZoomLevel(): Float = zoomLevel

    /**
     * Update the palette from native code.
     */
    fun updatePalette() {
        try {
            val nativePalette = NativeBridge.nativeGetPalette()
            if (nativePalette != null && nativePalette.size >= 16) {
                for (i in 0 until minOf(16, nativePalette.size)) {
                    // Native palette is RGB, add alpha - use safe access
                    val paletteValue = nativePalette.getOrNull(i) ?: 0
                    colorPalette[i] = 0xFF000000.toInt() or (paletteValue and 0xFFFFFF)
                }
                // Clear glyph cache since colors changed
                clearGlyphCache()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update palette: ${e.message}")
            // Keep default palette
        }
    }

    /**
     * Load the bitmap font data from native code.
     */
    fun loadFontBitmap() {
        try {
            val data = NativeBridge.nativeGetFontBitmap()
            if (data != null && data.size >= 3) {  // Need at least width, height, and some data
                val width = (data.getOrNull(0)?.toInt() ?: 0) and 0xFF
                val height = (data.getOrNull(1)?.toInt() ?: 0) and 0xFF
                // Validate dimensions are within reasonable bounds (1-64 pixels)
                if (width < 1 || width > 64 || height < 1 || height > 64) {
                    Log.e(TAG, "Invalid font dimensions: ${width}x${height}")
                    useBitmapFont = false
                    return
                }
                fontWidth = width
                fontHeight = height
                fontBitmap = data.copyOfRange(2, data.size)
                useBitmapFont = true
                hasLoggedFontWarning = false  // Reset warning flag on successful load
                Log.i(TAG, "Loaded bitmap font: ${fontWidth}x${fontHeight}, data size=${fontBitmap?.size}")

                // Clear glyph cache so it gets regenerated with new font
                clearGlyphCache()
            } else {
                Log.w(TAG, "No font bitmap data returned from native (data=${data?.size})")
                useBitmapFont = false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load font bitmap: ${e.message}")
            useBitmapFont = false
        }
    }

    /**
     * Create a bitmap for a single glyph with given colors.
     * This is now only called when the glyph is not in cache.
     */
    private fun createGlyphBitmap(charCode: Int, fgColor: Int, bgColor: Int): Bitmap {
        val bitmap = Bitmap.createBitmap(fontWidth, fontHeight, Bitmap.Config.ARGB_8888)
        val fontData = fontBitmap

        // Validate charCode is in valid range (0-255)
        val safeCharCode = charCode.coerceIn(0, 255)

        // If no font data or charCode out of bounds, return bitmap filled with background color
        if (fontData == null || fontData.isEmpty()) {
            bitmap.eraseColor(bgColor)
            return bitmap
        }

        // Safe multiplication to prevent overflow
        val charOffset = safeCharCode.toLong() * fontHeight.toLong()
        if (charOffset < 0 || charOffset > Int.MAX_VALUE ||
            charOffset + fontHeight > fontData.size) {
            bitmap.eraseColor(bgColor)
            return bitmap
        }

        // Validate pixel array size won't overflow
        val pixelCount = fontWidth.toLong() * fontHeight.toLong()
        if (pixelCount <= 0 || pixelCount > Int.MAX_VALUE) {
            bitmap.eraseColor(bgColor)
            return bitmap
        }

        val pixels = IntArray(pixelCount.toInt())
        val charOffsetInt = charOffset.toInt()  // Safe after bounds check above

        for (row in 0 until fontHeight) {
            // Validate fontData index before access
            val fontDataIdx = charOffsetInt + row
            if (fontDataIdx < 0 || fontDataIdx >= fontData.size) continue

            val rowByte = fontData[fontDataIdx].toInt() and 0xFF

            // Only process columns within 8-bit width (standard bitmap font)
            val maxCol = minOf(fontWidth, 8)
            for (col in 0 until maxCol) {
                // Safe bit shift: col is always 0..7
                val bit = (rowByte shr (7 - col)) and 1

                // Validate pixel index before write
                val pixelIdx = row.toLong() * fontWidth.toLong() + col.toLong()
                if (pixelIdx >= 0 && pixelIdx < pixels.size) {
                    pixels[pixelIdx.toInt()] = if (bit == 1) fgColor else bgColor
                }
            }

            // Fill remaining columns with background if fontWidth > 8
            for (col in maxCol until fontWidth) {
                val pixelIdx = row.toLong() * fontWidth.toLong() + col.toLong()
                if (pixelIdx >= 0 && pixelIdx < pixels.size) {
                    pixels[pixelIdx.toInt()] = bgColor
                }
            }
        }
        bitmap.setPixels(pixels, 0, fontWidth, 0, 0, fontWidth, fontHeight)
        return bitmap
    }

    /**
     * Get a glyph from cache or create and cache it.
     * Cache key combines charCode (8 bits), fgIndex (4 bits), bgIndex (4 bits).
     */
    private fun getCachedGlyph(charCode: Int, fgIndex: Int, bgIndex: Int): Bitmap {
        // Mask inputs to prevent overflow from out-of-range values
        // Explicit bit masking ensures key stays within expected range
        val safeCharCode = charCode and 0xFF          // 8 bits: 0-255
        val safeFgIndex = fgIndex.coerceIn(0, 15) and 0x0F  // 4 bits: 0-15
        val safeBgIndex = bgIndex.coerceIn(0, 15) and 0x0F  // 4 bits: 0-15
        val key = ((safeCharCode and 0xFF) shl 8) or ((safeFgIndex and 0x0F) shl 4) or (safeBgIndex and 0x0F)

        glyphCache.get(key)?.let { return it }

        // Not in cache, create and store it
        val glyph = createGlyphBitmap(safeCharCode, colorPalette[safeFgIndex], colorPalette[safeBgIndex])
        glyphCache.put(key, glyph)
        return glyph
    }

    /**
     * Clear the glyph cache (call when font or palette changes).
     */
    private fun clearGlyphCache() {
        glyphCache.evictAll()
        forceFullRedraw = true
    }

    /**
     * Reset all terminal state for a new connection.
     * Call this before connecting to a new BBS to ensure clean state.
     */
    fun resetState() {
        // Clear screen buffers
        screenBuffer = null
        previousBuffer = null

        // Reset cursor to home position
        cursorX = 1
        cursorY = 1
        cursorVisible = true
        cursorBlinkOn = true
        lastCursorBlink = 0L

        // Reset dirty region tracking
        dirtyMinX = 0
        dirtyMinY = 0
        dirtyMaxX = 0
        dirtyMaxY = 0
        hasDirtyRegion = false

        // Clear glyph cache and force full redraw
        clearGlyphCache()

        // Reset palette to defaults
        colorPalette[0] = 0xFF000000.toInt()   // Black
        colorPalette[1] = 0xFF0000AA.toInt()   // Blue
        colorPalette[2] = 0xFF00AA00.toInt()   // Green
        colorPalette[3] = 0xFF00AAAA.toInt()   // Cyan
        colorPalette[4] = 0xFFAA0000.toInt()   // Red
        colorPalette[5] = 0xFFAA00AA.toInt()   // Magenta
        colorPalette[6] = 0xFFAA5500.toInt()   // Brown
        colorPalette[7] = 0xFFAAAAAA.toInt()   // Light Gray
        colorPalette[8] = 0xFF555555.toInt()   // Dark Gray
        colorPalette[9] = 0xFF5555FF.toInt()   // Light Blue
        colorPalette[10] = 0xFF55FF55.toInt()  // Light Green
        colorPalette[11] = 0xFF55FFFF.toInt()  // Light Cyan
        colorPalette[12] = 0xFFFF5555.toInt()  // Light Red
        colorPalette[13] = 0xFFFF55FF.toInt()  // Light Magenta
        colorPalette[14] = 0xFFFFFF55.toInt()  // Yellow
        colorPalette[15] = 0xFFFFFFFF.toInt()  // White

        invalidate()
    }

    /**
     * Refresh the screen buffer from native code.
     * Uses dirty region tracking for optimized partial redraws.
     */
    fun refreshBuffer() {
        try {
            // Get dirty region FIRST, before getting buffer (buffer fetch clears dirty flag)
            val dirtyRegion = try {
                NativeBridge.nativeGetDirtyRegion()
            } catch (e: Exception) {
                null
            }

            val newBuffer = NativeBridge.nativeGetScreenBuffer()
            if (newBuffer == null) {
                // Native buffer not ready - keep existing buffer and trigger redraw anyway
                // This helps during foldable transitions where native may temporarily return null
                if (screenBuffer != null) {
                    invalidate()
                }
                return
            }

            // Validate buffer size matches expected screen dimensions
            // This catches cases where native resize is in progress
            val screenSize = try {
                NativeBridge.nativeGetScreenSize()
            } catch (e: Exception) {
                null
            }
            val screenWidth = screenSize?.getOrNull(0) ?: termWidth
            val screenHeight = screenSize?.getOrNull(1) ?: termHeight

            if (screenSize != null && screenSize.size >= 2 && screenWidth > 0 && screenHeight > 0) {
                val expectedSize = screenWidth.toLong() * screenHeight.toLong()
                if (newBuffer.size.toLong() != expectedSize) {
                    // Buffer size mismatch - native resize may be in progress
                    // Keep existing buffer and schedule a retry
                    Log.d(TAG, "Buffer size mismatch: got ${newBuffer.size}, expected $expectedSize")
                    postDelayed({ refreshBuffer() }, 50)
                    return
                }
            }

            // Get cursor position safely (handle null or empty array)
            val pos = try {
                NativeBridge.nativeGetCursorPos()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to get cursor position: ${e.message}")
                null
            }
            val newCursorX = pos?.getOrNull(0) ?: cursorX
            val newCursorY = pos?.getOrNull(1) ?: cursorY
            val cursorMoved = (newCursorX != cursorX || newCursorY != cursorY)

            cursorX = newCursorX
            cursorY = newCursorY
            cursorVisible = NativeBridge.nativeIsCursorVisible()

            val prevBuffer = previousBuffer
            var hasChanges = forceFullRedraw || cursorMoved

            if (forceFullRedraw) {
                // Full redraw - mark entire screen as dirty region
                hasDirtyRegion = true
                dirtyMinX = 0
                dirtyMinY = 0
                dirtyMaxX = screenWidth - 1
                dirtyMaxY = screenHeight - 1
                forceFullRedraw = false
                hasChanges = true
            } else if (dirtyRegion != null && dirtyRegion.size >= 4) {
                // Use native dirty region for optimized comparison
                val nativeMinX = dirtyRegion[0].coerceIn(0, screenWidth - 1)
                val nativeMinY = dirtyRegion[1].coerceIn(0, screenHeight - 1)
                val nativeMaxX = dirtyRegion[2].coerceIn(0, screenWidth - 1)
                val nativeMaxY = dirtyRegion[3].coerceIn(0, screenHeight - 1)

                // Only compare cells in the dirty region
                if (prevBuffer != null && prevBuffer.size == newBuffer.size) {
                    for (y in nativeMinY..nativeMaxY) {
                        for (x in nativeMinX..nativeMaxX) {
                            val idx = y * screenWidth + x
                            if (idx < newBuffer.size && newBuffer[idx] != prevBuffer[idx]) {
                                hasChanges = true
                                break
                            }
                        }
                        if (hasChanges) break
                    }
                } else {
                    hasChanges = true
                }

                if (hasChanges) {
                    hasDirtyRegion = true
                    dirtyMinX = nativeMinX
                    dirtyMinY = nativeMinY
                    dirtyMaxX = nativeMaxX
                    dirtyMaxY = nativeMaxY
                }
            } else if (!hasChanges && prevBuffer != null && prevBuffer.size == newBuffer.size) {
                // No dirty region info - fall back to linear scan but stop early
                for (i in newBuffer.indices) {
                    if (newBuffer[i] != prevBuffer[i]) {
                        hasChanges = true
                        // Mark entire screen as dirty since we don't know what changed
                        hasDirtyRegion = true
                        dirtyMinX = 0
                        dirtyMinY = 0
                        dirtyMaxX = screenWidth - 1
                        dirtyMaxY = screenHeight - 1
                        break
                    }
                }
            } else if (hasChanges) {
                // Cursor moved or buffer size changed - full redraw
                hasDirtyRegion = true
                dirtyMinX = 0
                dirtyMinY = 0
                dirtyMaxX = screenWidth - 1
                dirtyMaxY = screenHeight - 1
            }

            // Store current buffer for next comparison
            previousBuffer = newBuffer.copyOf()
            screenBuffer = newBuffer

            // Scan for URLs when content changes
            if (hasChanges) {
                detectUrls()
                invalidate()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to refresh buffer: ${e.message}")
        }
    }

    /**
     * Force a full redraw on next frame (call after zoom, font change, screen resume, etc.)
     * Also refreshes the buffer from native to ensure we have current data.
     */
    fun forceRedraw() {
        forceFullRedraw = true
        refreshBuffer()  // Get fresh buffer and trigger invalidate
        // Always invalidate even if refreshBuffer didn't (e.g., if native returned null)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        // Always draw background first (full canvas, not translated)
        canvas.drawColor(colorPalette[0])

        val buffer = screenBuffer
        if (buffer == null || buffer.isEmpty()) {
            // No buffer yet - just show black background
            return
        }

        // Update cursor blink
        val now = System.currentTimeMillis()
        val cursorBlinkChanged = (now - lastCursorBlink > cursorBlinkInterval)
        if (cursorBlinkChanged) {
            cursorBlinkOn = !cursorBlinkOn
            lastCursorBlink = now
        }

        // Get screen size safely with null and bounds checking
        val size = try {
            NativeBridge.nativeGetScreenSize()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get screen size: ${e.message}")
            return
        }

        if (size == null || size.size < 2) {
            return  // Silent return - not necessarily an error, native might not be ready
        }

        val screenWidth = size.getOrNull(0) ?: return
        val screenHeight = size.getOrNull(1) ?: return

        if (screenWidth <= 0 || screenHeight <= 0) {
            return
        }

        // Apply pan offset for zoomed view
        canvas.save()
        canvas.translate(panOffsetX, panOffsetY)

        // Check if we're showing scrollback content
        if (scrollbackOffset > 0) {
            // Get scrollback buffer for the visible portion
            val scrollbackBuffer = try {
                NativeBridge.nativeGetScrollbackBuffer(scrollbackOffset - 1, termHeight)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to get scrollback buffer: ${e.message}")
                null
            }

            // Snapshot scrollbackCols to avoid race with updateScrollbackInfo()
            val sbCols = scrollbackCols
            if (scrollbackBuffer != null && sbCols > 0) {
                // Draw scrollback content with safe index calculation
                val linesToDraw = minOf(termHeight, scrollbackBuffer.size / sbCols)
                for (y in 0 until linesToDraw) {
                    for (x in 0 until minOf(sbCols, termWidth)) {
                        // Use Long arithmetic to prevent overflow
                        val idxLong = y.toLong() * sbCols.toLong() + x.toLong()
                        if (idxLong >= 0 && idxLong < scrollbackBuffer.size) {
                            val cell = scrollbackBuffer[idxLong.toInt()]
                            drawCell(canvas, x, y, cell)
                        }
                    }
                }
            } else {
                // Fallback: draw current screen if scrollback fails
                drawCurrentScreen(canvas, buffer, screenWidth, screenHeight)
            }

            // Don't draw cursor when scrolled back
        } else {
            // Normal live view - draw current screen
            drawCurrentScreen(canvas, buffer, screenWidth, screenHeight)

            // Draw cursor (only if user preference allows and BBS cursor is visible)
            if (showCursor && cursorVisible && cursorBlinkOn) {
                drawCursor(canvas, screenWidth)
            }
        }

        canvas.restore()

        // Draw scrollback indicator if scrolled back
        if (scrollbackOffset > 0) {
            drawScrollbackIndicator(canvas)
        }

        // Schedule next frame for cursor blink only (if animating)
        if (showCursor && cursorVisible && isAnimating) {
            postInvalidateDelayed(cursorBlinkInterval)
        }
    }

    /**
     * Pause cursor animation (call from Activity.onPause).
     */
    fun pauseAnimation() {
        isAnimating = false
    }

    /**
     * Resume cursor animation (call from Activity.onResume).
     */
    fun resumeAnimation() {
        isAnimating = true
        if (showCursor && cursorVisible) {
            invalidate()
        }
    }

    /**
     * Toggle cursor visibility (user preference).
     */
    fun toggleCursor(): Boolean {
        showCursor = !showCursor
        invalidate()
        return showCursor
    }

    /**
     * Check if cursor is enabled (user preference).
     */
    fun isCursorEnabled(): Boolean = showCursor

    /**
     * Draw the current live screen content.
     */
    private fun drawCurrentScreen(canvas: Canvas, buffer: IntArray, screenWidth: Int, screenHeight: Int) {
        for (y in 0 until minOf(screenHeight, termHeight)) {
            for (x in 0 until minOf(screenWidth, termWidth)) {
                val idx = y.toLong() * screenWidth.toLong() + x.toLong()
                if (idx < 0 || idx >= buffer.size) continue

                val cell = buffer[idx.toInt()]
                drawCell(canvas, x, y, cell)
            }
        }
    }

    /**
     * Draw scrollback indicator showing we're viewing history.
     */
    private fun drawScrollbackIndicator(canvas: Canvas) {
        val indicatorPaint = Paint().apply {
            color = 0xCC000000.toInt()  // Semi-transparent black
            style = Paint.Style.FILL
        }
        val textPaint = Paint().apply {
            color = 0xFFFFFF00.toInt()  // Yellow
            textSize = 32f
            textAlign = Paint.Align.CENTER
            isAntiAlias = true
        }

        // Draw indicator bar at top
        val barHeight = 44f
        canvas.drawRect(0f, 0f, width.toFloat(), barHeight, indicatorPaint)

        // Draw text
        val text = "↑ SCROLLBACK: $scrollbackOffset lines back (tap to return)"
        canvas.drawText(text, width / 2f, 30f, textPaint)
    }

    /**
     * Draw a single terminal cell using cached glyphs.
     */
    private fun drawCell(canvas: Canvas, x: Int, y: Int, cell: Int) {
        val ch = NativeBridge.unpackChar(cell)
        val attr = NativeBridge.unpackAttr(cell)

        // Get colors from attribute - background can use all 16 colors with blink bit
        val fgIndex = NativeBridge.attrToFg(attr).coerceIn(0, 15)
        val bgIndex = NativeBridge.attrToBg(attr).coerceIn(0, 15)

        val left = x * cellWidth
        val top = y * cellHeight
        val right = left + cellWidth
        val bottom = top + cellHeight

        // Use bitmap font rendering with glyph cache if available
        val fontData = fontBitmap
        if (useBitmapFont && fontData != null && fontData.isNotEmpty()) {
            val charCode = ch.code and 0xFF

            // Get cached glyph (creates and caches if not found)
            val glyph = getCachedGlyph(charCode, fgIndex, bgIndex)
            val srcRect = Rect(0, 0, fontWidth, fontHeight)
            val dstRect = Rect(left.toInt(), top.toInt(), right.toInt(), bottom.toInt())
            canvas.drawBitmap(glyph, srcRect, dstRect, bitmapPaint)
            // Note: Do NOT recycle - glyph is cached for reuse
        } else {
            // Log once if bitmap font not available (avoid log spam)
            if (!hasLoggedFontWarning) {
                Log.w(TAG, "Bitmap font not available: useBitmapFont=$useBitmapFont, fontBitmap size=${fontData?.size}")
                hasLoggedFontWarning = true
            }
            // Fallback to text rendering
            // Draw background (only compute color when needed)
            if (bgIndex != 0) {
                bgPaint.color = colorPalette[bgIndex]
                canvas.drawRect(left, top, right, bottom, bgPaint)
            }

            // Draw character using CP437 mapping
            val displayChar = mapCP437Char(ch.code)
            if ((displayChar.code > 0 && displayChar != ' ') || ch.code == 32) {
                textPaint.color = colorPalette[fgIndex]
                canvas.drawText(displayChar.toString(), left, top + textBaseline, textPaint)
            }
        }
    }

    /**
     * Set font type based on font name.
     */
    fun setFontByName(fontName: String) {
        currentFontType = when {
            fontName.contains("Amiga", ignoreCase = true) -> FontType.AMIGA
            fontName.contains("Topaz", ignoreCase = true) -> FontType.AMIGA
            fontName.contains("P0T NOoDLE", ignoreCase = true) -> FontType.AMIGA
            fontName.contains("MicroKnight", ignoreCase = true) -> FontType.AMIGA
            fontName.contains("mO'sOul", ignoreCase = true) -> FontType.AMIGA
            else -> FontType.CP437
        }

        // Load bitmap font immediately (native font should already be set)
        loadFontBitmap()
        invalidate()
    }

    /**
     * Complete CP437 to Unicode mapping table.
     */
    private val cp437ToUnicode = charArrayOf(
        // 0-31: Control characters / symbols
        '\u0000', '\u263A', '\u263B', '\u2665', '\u2666', '\u2663', '\u2660', '\u2022',
        '\u25D8', '\u25CB', '\u25D9', '\u2642', '\u2640', '\u266A', '\u266B', '\u263C',
        '\u25BA', '\u25C4', '\u2195', '\u203C', '\u00B6', '\u00A7', '\u25AC', '\u21A8',
        '\u2191', '\u2193', '\u2192', '\u2190', '\u221F', '\u2194', '\u25B2', '\u25BC',
        // 32-127: Standard ASCII (will use directly)
        ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
        '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
        '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
        'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '\u2302',
        // 128-175: Extended ASCII
        '\u00C7', '\u00FC', '\u00E9', '\u00E2', '\u00E4', '\u00E0', '\u00E5', '\u00E7',
        '\u00EA', '\u00EB', '\u00E8', '\u00EF', '\u00EE', '\u00EC', '\u00C4', '\u00C5',
        '\u00C9', '\u00E6', '\u00C6', '\u00F4', '\u00F6', '\u00F2', '\u00FB', '\u00F9',
        '\u00FF', '\u00D6', '\u00DC', '\u00A2', '\u00A3', '\u00A5', '\u20A7', '\u0192',
        '\u00E1', '\u00ED', '\u00F3', '\u00FA', '\u00F1', '\u00D1', '\u00AA', '\u00BA',
        '\u00BF', '\u2310', '\u00AC', '\u00BD', '\u00BC', '\u00A1', '\u00AB', '\u00BB',
        // 176-223: Box drawing and blocks
        '\u2591', '\u2592', '\u2593', '\u2502', '\u2524', '\u2561', '\u2562', '\u2556',
        '\u2555', '\u2563', '\u2551', '\u2557', '\u255D', '\u255C', '\u255B', '\u2510',
        '\u2514', '\u2534', '\u252C', '\u251C', '\u2500', '\u253C', '\u255E', '\u255F',
        '\u255A', '\u2554', '\u2569', '\u2566', '\u2560', '\u2550', '\u256C', '\u2567',
        '\u2568', '\u2564', '\u2565', '\u2559', '\u2558', '\u2552', '\u2553', '\u256B',
        '\u256A', '\u2518', '\u250C', '\u2588', '\u2584', '\u258C', '\u2590', '\u2580',
        // 224-255: Greek letters and math symbols
        '\u03B1', '\u00DF', '\u0393', '\u03C0', '\u03A3', '\u03C3', '\u00B5', '\u03C4',
        '\u03A6', '\u0398', '\u03A9', '\u03B4', '\u221E', '\u03C6', '\u03B5', '\u2229',
        '\u2261', '\u00B1', '\u2265', '\u2264', '\u2320', '\u2321', '\u00F7', '\u2248',
        '\u00B0', '\u2219', '\u00B7', '\u221A', '\u207F', '\u00B2', '\u25A0', '\u00A0'
    )

    /**
     * Amiga character set to Unicode mapping table.
     * Amiga uses ISO 8859-1 (Latin-1) for 128-255, with custom chars for 0-31.
     */
    private val amigaToUnicode = charArrayOf(
        // 0-31: Amiga control/graphics characters
        '\u0000', '\u0001', '\u0002', '\u0003', '\u0004', '\u0005', '\u0006', '\u0007',
        '\u0008', '\u0009', '\u000A', '\u000B', '\u000C', '\u000D', '\u000E', '\u000F',
        '\u0010', '\u0011', '\u0012', '\u0013', '\u0014', '\u0015', '\u0016', '\u0017',
        '\u0018', '\u0019', '\u001A', '\u001B', '\u001C', '\u001D', '\u001E', '\u001F',
        // 32-127: Standard ASCII
        ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
        '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
        '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
        'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '\u2302',
        // 128-159: ISO 8859-1 control chars (display as spaces or special)
        '\u00C7', '\u00FC', '\u00E9', '\u00E2', '\u00E4', '\u00E0', '\u00E5', '\u00E7',
        '\u00EA', '\u00EB', '\u00E8', '\u00EF', '\u00EE', '\u00EC', '\u00C4', '\u00C5',
        '\u00C9', '\u00E6', '\u00C6', '\u00F4', '\u00F6', '\u00F2', '\u00FB', '\u00F9',
        '\u00FF', '\u00D6', '\u00DC', '\u00A2', '\u00A3', '\u00A5', '\u20A7', '\u0192',
        // 160-191: ISO 8859-1 Latin characters
        '\u00A0', '\u00A1', '\u00A2', '\u00A3', '\u00A4', '\u00A5', '\u00A6', '\u00A7',
        '\u00A8', '\u00A9', '\u00AA', '\u00AB', '\u00AC', '\u00AD', '\u00AE', '\u00AF',
        '\u00B0', '\u00B1', '\u00B2', '\u00B3', '\u00B4', '\u00B5', '\u00B6', '\u00B7',
        '\u00B8', '\u00B9', '\u00BA', '\u00BB', '\u00BC', '\u00BD', '\u00BE', '\u00BF',
        // 192-223: ISO 8859-1 uppercase accented
        '\u00C0', '\u00C1', '\u00C2', '\u00C3', '\u00C4', '\u00C5', '\u00C6', '\u00C7',
        '\u00C8', '\u00C9', '\u00CA', '\u00CB', '\u00CC', '\u00CD', '\u00CE', '\u00CF',
        '\u00D0', '\u00D1', '\u00D2', '\u00D3', '\u00D4', '\u00D5', '\u00D6', '\u00D7',
        '\u00D8', '\u00D9', '\u00DA', '\u00DB', '\u00DC', '\u00DD', '\u00DE', '\u00DF',
        // 224-255: ISO 8859-1 lowercase accented
        '\u00E0', '\u00E1', '\u00E2', '\u00E3', '\u00E4', '\u00E5', '\u00E6', '\u00E7',
        '\u00E8', '\u00E9', '\u00EA', '\u00EB', '\u00EC', '\u00ED', '\u00EE', '\u00EF',
        '\u00F0', '\u00F1', '\u00F2', '\u00F3', '\u00F4', '\u00F5', '\u00F6', '\u00F7',
        '\u00F8', '\u00F9', '\u00FA', '\u00FB', '\u00FC', '\u00FD', '\u00FE', '\u00FF'
    )

    /**
     * Map character codes to Unicode based on current font type.
     */
    private fun mapChar(code: Int): Char {
        return when (currentFontType) {
            FontType.AMIGA -> if (code in 0..255) amigaToUnicode[code] else ' '
            FontType.CP437 -> if (code in 0..255) cp437ToUnicode[code] else ' '
        }
    }

    /**
     * Map CP437 character codes to Unicode equivalents (legacy, uses current font).
     */
    private fun mapCP437Char(code: Int): Char {
        return mapChar(code)
    }

    /**
     * Draw the cursor at current position using cached glyphs.
     */
    private fun drawCursor(canvas: Canvas, screenWidth: Int) {
        val x = (cursorX - 1).coerceIn(0, termWidth - 1)
        val y = (cursorY - 1).coerceIn(0, termHeight - 1)

        val left = x * cellWidth
        val top = y * cellHeight
        val right = left + cellWidth
        val bottom = top + cellHeight

        // Redraw the character with inverted colors (cursor = light gray bg, black fg)
        val buffer = screenBuffer
        val fontData = fontBitmap
        if (buffer != null && screenWidth > 0) {
            // Safe index calculation using Long to prevent overflow
            val idxLong = y.toLong() * screenWidth.toLong() + x.toLong()
            if (idxLong >= 0 && idxLong < buffer.size) {
                val idx = idxLong.toInt()
                val cell = buffer[idx]
                val ch = NativeBridge.unpackChar(cell)
                val charCode = ch.code and 0xFF

                if (useBitmapFont && fontData != null) {
                    // Draw with inverted colors using cached glyph (fg=black/0, bg=light gray/7)
                    val glyph = getCachedGlyph(charCode, 0, 7)
                    val srcRect = Rect(0, 0, fontWidth, fontHeight)
                    val dstRect = Rect(left.toInt(), top.toInt(), right.toInt(), bottom.toInt())
                    canvas.drawBitmap(glyph, srcRect, dstRect, bitmapPaint)
                    // Note: Do NOT recycle - glyph is cached for reuse
                } else {
                    // Fallback: Draw cursor as a filled rectangle
                    cursorPaint.color = colorPalette[7] // Light gray
                    canvas.drawRect(left, top, right, bottom, cursorPaint)

                    val displayChar = mapCP437Char(ch.code)
                    if (displayChar.code > 0 && displayChar != '\u0000') {
                        textPaint.color = colorPalette[0] // Black on cursor
                        canvas.drawText(displayChar.toString(), left, top + textBaseline, textPaint)
                    }
                }
            }
        } else {
            // No buffer, just draw cursor block
            cursorPaint.color = colorPalette[7]
            canvas.drawRect(left, top, right, bottom, cursorPaint)
        }
    }

    /**
     * Set terminal dimensions.
     * For BBS use, recommend keeping at 80x25.
     */
    fun setTerminalSize(cols: Int, rows: Int) {
        termWidth = cols.coerceIn(40, 132)
        termHeight = rows.coerceIn(24, 60)
        calculateCellSize()
        invalidate()
    }

    /**
     * Get current terminal dimensions.
     */
    fun getTerminalSize(): Pair<Int, Int> = Pair(termWidth, termHeight)

    /**
     * Get the actual content bounds of the terminal in pixels.
     * Returns (width, height) of just the terminal content area, excluding any black padding.
     */
    fun getContentBounds(): Pair<Int, Int> {
        val contentWidth = (termWidth * cellWidth).toInt()
        val contentHeight = (termHeight * cellHeight).toInt()
        return Pair(contentWidth, contentHeight)
    }

    // Keyboard input handling
    var onCharacterInput: ((Char) -> Unit)? = null
    var onKeyInput: ((Int) -> Unit)? = null

    override fun onCheckIsTextEditor(): Boolean = true

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
        // Use VISIBLE_PASSWORD to disable auto-caps and suggestions
        outAttrs.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN or
                              EditorInfo.IME_FLAG_NO_EXTRACT_UI or
                              EditorInfo.IME_ACTION_NONE
        outAttrs.initialCapsMode = 0  // No auto-caps

        return object : BaseInputConnection(this, false) {
            override fun commitText(text: CharSequence?, newCursorPosition: Int): Boolean {
                text?.forEach { c ->
                    onCharacterInput?.invoke(c)
                }
                return true
            }

            override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                repeat(beforeLength) {
                    onKeyInput?.invoke(8) // Backspace
                }
                return true
            }

            override fun sendKeyEvent(event: KeyEvent): Boolean {
                if (event.action == KeyEvent.ACTION_DOWN) {
                    // Explicit Enter key check - some IMEs send KEYCODE_ENTER
                    // without a unicodeChar
                    if (event.keyCode == KeyEvent.KEYCODE_ENTER) {
                        onKeyInput?.invoke(13) // CR
                        return true
                    }
                    val char = event.unicodeChar
                    if (char != 0) {
                        onCharacterInput?.invoke(char.toChar())
                        return true
                    }
                }
                return super.sendKeyEvent(event)
            }

            override fun performEditorAction(actionCode: Int): Boolean {
                // Some IMEs dispatch Enter as an editor action instead of a key event
                onKeyInput?.invoke(13) // CR
                return true
            }

            override fun getCursorCapsMode(reqModes: Int): Int = 0  // Never auto-caps
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        // Let scale gesture detector handle pinch-to-zoom
        scaleGestureDetector.onTouchEvent(event)

        // Track if we're in a scaling gesture
        if (event.pointerCount > 1) {
            isScaling = true
        } else if (event.action == MotionEvent.ACTION_UP || event.action == MotionEvent.ACTION_CANCEL) {
            isScaling = false
        }

        // Only pass to gesture detector if not scaling (single finger)
        if (!isScaling && !scaleGestureDetector.isInProgress) {
            val handled = gestureDetector.onTouchEvent(event)

            // If gesture detector didn't handle it and it's a tap, show keyboard
            if (!handled && event.action == MotionEvent.ACTION_UP) {
                performClick()
            }
        }

        return true  // Always consume touch events
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    /**
     * Handle a tap at the given coordinates.
     * Returns true if a URL was tapped or scrollback was dismissed.
     */
    private fun handleTap(x: Float, y: Float): Boolean {
        // If scrolled back, tap returns to live view
        if (scrollbackOffset > 0) {
            jumpToLive()
            return true
        }

        if (cellWidth <= 0 || cellHeight <= 0) return false

        // Adjust for pan offset - convert screen coordinates to content coordinates
        val contentX = x - panOffsetX
        val contentY = y - panOffsetY

        // Convert pixel coordinates to cell coordinates
        val col = (contentX / cellWidth).toInt()
        val row = (contentY / cellHeight).toInt()

        // Bounds check
        if (col < 0 || col >= termWidth || row < 0 || row >= termHeight) {
            return false
        }

        // Check if tap hit any detected URL
        for (urlRegion in detectedUrls) {
            if (isPointInUrlRegion(row, col, urlRegion)) {
                onUrlTapped?.invoke(urlRegion.url)
                return true
            }
        }

        // No URL hit - show keyboard (existing behavior)
        return false
    }

    /**
     * Check if a cell position is within a URL region.
     */
    private fun isPointInUrlRegion(row: Int, col: Int, region: UrlRegion): Boolean {
        // Single row URL
        if (region.startRow == region.endRow) {
            return row == region.startRow && col >= region.startCol && col <= region.endCol
        }

        // Multi-row URL (wrapped)
        if (row == region.startRow) {
            return col >= region.startCol
        }
        if (row == region.endRow) {
            return col <= region.endCol
        }
        return row > region.startRow && row < region.endRow
    }

    /**
     * Scan the screen buffer for URLs.
     * Called after each buffer refresh.
     */
    private fun detectUrls() {
        val buffer = screenBuffer
        if (buffer == null) {
            detectedUrls = emptyList()  // Clear old URLs when buffer is null
            return
        }

        val size = try {
            NativeBridge.nativeGetScreenSize()
        } catch (e: Exception) {
            detectedUrls = emptyList()  // Clear old URLs on error
            return
        }

        if (size == null || size.size < 2) {
            detectedUrls = emptyList()  // Clear old URLs when size invalid
            return
        }

        val screenWidth = size.getOrNull(0)
        val screenHeight = size.getOrNull(1)

        if (screenWidth == null || screenHeight == null || screenWidth <= 0 || screenHeight <= 0) {
            detectedUrls = emptyList()  // Clear old URLs when dimensions invalid
            return
        }

        // Build text representation of screen, tracking positions
        val screenText = StringBuilder()
        val positionMap = mutableListOf<Pair<Int, Int>>()  // Maps string index to (row, col)

        for (y in 0 until minOf(screenHeight, termHeight)) {
            for (x in 0 until minOf(screenWidth, termWidth)) {
                val idx = y.toLong() * screenWidth.toLong() + x.toLong()
                if (idx < 0 || idx >= buffer.size) {
                    screenText.append(' ')
                } else {
                    val cell = buffer[idx.toInt()]
                    val ch = NativeBridge.unpackChar(cell)
                    val mappedChar = mapChar(ch.code)
                    screenText.append(if (mappedChar.code in 32..126) mappedChar else ' ')
                }
                positionMap.add(Pair(y, x))
            }
            // Don't add newline - we track positions directly
        }

        // Find all URLs in the screen text
        val urls = mutableListOf<UrlRegion>()
        for (match in urlPattern.findAll(screenText)) {
            val startIdx = match.range.first
            val endIdx = match.range.last

            if (startIdx < positionMap.size && endIdx < positionMap.size) {
                val (startRow, startCol) = positionMap[startIdx]
                val (endRow, endCol) = positionMap[endIdx]

                var url = match.value
                // Add https:// prefix if URL starts with www.
                if (url.startsWith("www.", ignoreCase = true)) {
                    url = "https://$url"
                }

                urls.add(UrlRegion(url, startRow, startCol, endRow, endCol))
            }
        }

        detectedUrls = urls
    }

    /**
     * Get list of currently detected URLs (for debugging/display).
     */
    fun getDetectedUrls(): List<String> = detectedUrls.map { it.url }

    /**
     * Update scrollback buffer info from native.
     */
    private fun updateScrollbackInfo() {
        try {
            val info = NativeBridge.nativeGetScrollbackInfo()
            if (info != null && info.size >= 3) {
                scrollbackAvailable = info[0]  // Filled lines
                scrollbackCols = info[2]       // Columns
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get scrollback info: ${e.message}")
        }
    }

    /**
     * Notify listener of scrollback state change.
     */
    private fun notifyScrollbackStateChanged() {
        onScrollbackStateChanged?.invoke(
            scrollbackOffset > 0,
            scrollbackOffset,
            scrollbackAvailable
        )
    }

    /**
     * Check if currently scrolled back in history.
     */
    fun isScrolledBack(): Boolean = scrollbackOffset > 0

    /**
     * Get current scrollback offset (lines back from live).
     */
    fun getScrollbackOffset(): Int = scrollbackOffset

    /**
     * Jump back to live view (clear scrollback offset).
     */
    fun jumpToLive() {
        if (scrollbackOffset > 0) {
            scrollbackOffset = 0
            notifyScrollbackStateChanged()
            invalidate()
        }
    }

    /**
     * Scroll the scrollback buffer by a number of lines.
     * Positive = scroll back into history, negative = scroll toward live.
     */
    fun scrollByLines(lines: Int) {
        updateScrollbackInfo()
        val newOffset = (scrollbackOffset + lines).coerceIn(0, scrollbackAvailable)
        if (newOffset != scrollbackOffset) {
            scrollbackOffset = newOffset
            notifyScrollbackStateChanged()
            invalidate()
        }
    }

    /**
     * Called when user types - should return to live view.
     */
    fun onUserInput() {
        jumpToLive()
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        // Clear callbacks to prevent memory leaks
        onTerminalSizeChanged = null
        onCharacterInput = null
        onKeyInput = null
        onUrlTapped = null
        onScrollbackStateChanged = null
        // Stop animation
        isAnimating = false
    }
}
