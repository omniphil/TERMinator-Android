package com.syncterm.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.Shader
import android.graphics.Typeface
import android.util.AttributeSet
import android.view.View
import androidx.core.content.res.ResourcesCompat
import kotlin.random.Random

/**
 * Custom CRT-style scrolling marquee with scanlines and glitch effects.
 * Text scrolls from right to left, entering from the right edge.
 */
class CrtMarqueeView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    // Load retro pixel font
    private val retroFont: Typeface? = try {
        ResourcesCompat.getFont(context, R.font.press_start_2p)
    } catch (e: Exception) {
        null  // Fall back to monospace if font not available
    }

    private val textPaint = Paint().apply {  // No anti-alias for chunky CRT look
        color = Color.parseColor("#66EE66")  // Brighter green
        textSize = 42f  // Will be set properly in onSizeChanged
        typeface = retroFont ?: Typeface.MONOSPACE
    }

    private val scanlinePaint = Paint().apply {
        color = Color.parseColor("#40000000")  // Darker scanlines for worn look
        strokeWidth = 1f
    }

    private val glowPaint = Paint().apply {
        color = Color.parseColor("#66EE66")  // Match green
        textSize = 42f
        typeface = retroFont ?: Typeface.MONOSPACE
        maskFilter = android.graphics.BlurMaskFilter(4f, android.graphics.BlurMaskFilter.Blur.NORMAL)
    }

    // Noise/flicker paint for worn effect
    private val noisePaint = Paint().apply {
        color = Color.parseColor("#15000000")
    }

    // For per-character rendering
    private val charWidths = FloatArray(1)

    private var text: String = ""
    private var textWidth: Float = 0f
    private var scrollX: Float = 0f
    private var scrollSpeed: Float = 2.5f  // pixels per frame (25% faster)

    private var lastFrameTime: Long = 0
    private var isScrolling = false

    // Glitch effect
    private var glitchOffsetY: Float = 0f
    private var glitchOffsetX: Float = 0f
    private var glitchAlpha: Int = 255
    private var nextGlitchTime: Long = 0
    private var isGlitching = false
    private var glitchDuration: Long = 0

    // Scanline spacing
    private val scanlineSpacing = 2

    // Base brightness (worn phosphor look)
    private var baseAlpha: Int = 200  // Not full brightness - worn phosphor

    // Per-character glitch state (updated periodically, not every frame)
    private var charGlitchAlphas: IntArray = IntArray(0)
    private var charCaseFlips: BooleanArray = BooleanArray(0)
    private var lastCharGlitchUpdate: Long = 0
    private val charGlitchInterval: Long = 250  // Update character glitches every 250ms

    // Micro-jitter for constant horizontal instability
    private var microJitterX: Float = 0f
    private var lastMicroJitterUpdate: Long = 0
    private val microJitterInterval: Long = 50  // Update jitter every 50ms (more frequent)

    fun setText(newText: String) {
        text = newText
        textWidth = textPaint.measureText(text)
        // Initialize per-character glitch arrays
        charGlitchAlphas = IntArray(text.length) { 0 }
        charCaseFlips = BooleanArray(text.length) { false }
        updateCharacterGlitches()
        // Start text off-screen to the right
        scrollX = width.toFloat()
        invalidate()
    }

    private fun updateCharacterGlitches() {
        // Reset all to normal
        for (i in charGlitchAlphas.indices) {
            charGlitchAlphas[i] = 0  // 0 means normal brightness
            charCaseFlips[i] = false
        }

        // Pick 5-10 random characters to be DIMMER (weak phosphor)
        val numDimChars = Random.nextInt(5, 11)
        repeat(numDimChars) {
            if (text.isNotEmpty()) {
                val idx = Random.nextInt(text.length)
                // Very dim - extremely noticeable
                charGlitchAlphas[idx] = Random.nextInt(-160, -100)
            }
        }

        // Pick 3-6 random characters to be BRIGHTER (hot spots)
        val numBrightChars = Random.nextInt(3, 7)
        repeat(numBrightChars) {
            if (text.isNotEmpty()) {
                val idx = Random.nextInt(text.length)
                // Much brighter than normal
                charGlitchAlphas[idx] = Random.nextInt(50, 80)
            }
        }

        // Pick 0-2 random letter characters to flip case
        val numCaseFlips = Random.nextInt(0, 3)
        repeat(numCaseFlips) {
            if (text.isNotEmpty()) {
                val idx = Random.nextInt(text.length)
                if (text[idx].isLetter()) {
                    charCaseFlips[idx] = true
                }
            }
        }

        lastCharGlitchUpdate = System.currentTimeMillis()
    }

    private fun updateMicroJitter() {
        // Random horizontal offset that changes frequently - pronounced jitter
        microJitterX = Random.nextFloat() * 12f - 6f  // ±6 pixels
        lastMicroJitterUpdate = System.currentTimeMillis()
    }

    fun startScrolling() {
        isScrolling = true
        lastFrameTime = System.currentTimeMillis()
        scrollX = width.toFloat()  // Start from right edge
        scheduleNextGlitch()
        invalidate()
    }

    fun stopScrolling() {
        isScrolling = false
    }

    private fun scheduleNextGlitch() {
        // Random glitch every 3-8 seconds
        nextGlitchTime = System.currentTimeMillis() + Random.nextLong(3000, 8000)
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        // Set text size to about 60% of view height for good visibility
        val newTextSize = h * 0.6f
        textPaint.textSize = newTextSize
        glowPaint.textSize = newTextSize
        textWidth = textPaint.measureText(text)
        // Start from right edge
        scrollX = w.toFloat()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        // Background set via XML to @drawable/grid_pattern

        val currentTime = System.currentTimeMillis()

        // Update per-character glitches periodically (not every frame)
        if (currentTime - lastCharGlitchUpdate >= charGlitchInterval) {
            updateCharacterGlitches()
        }

        // Update micro-jitter for horizontal instability
        if (currentTime - lastMicroJitterUpdate >= microJitterInterval) {
            updateMicroJitter()
        }

        // Handle glitch timing
        if (!isGlitching && currentTime >= nextGlitchTime) {
            isGlitching = true
            glitchDuration = Random.nextLong(50, 200)
            glitchOffsetY = Random.nextFloat() * 4f - 2f
            glitchOffsetX = Random.nextFloat() * 8f - 4f  // Horizontal jitter ±4 pixels
            glitchAlpha = Random.nextInt(120, 180)
        }

        if (isGlitching) {
            if (currentTime >= nextGlitchTime + glitchDuration) {
                isGlitching = false
                glitchOffsetY = 0f
                glitchOffsetX = 0f
                glitchAlpha = baseAlpha
                scheduleNextGlitch()
            }
        }

        // Calculate text Y position (vertically centered)
        val textY = (height + textPaint.textSize) / 2f - textPaint.descent()

        // Apply glitch offsets (big glitch + constant micro-jitter)
        val drawY = textY + glitchOffsetY
        val drawXOffset = glitchOffsetX + microJitterX

        // Calculate base effective alpha (no global flicker - only per-character variation)
        val effectiveAlpha = if (isGlitching) {
            glitchAlpha
        } else {
            baseAlpha
        }

        // Save layer for text + scanlines (scanlines only affect text pixels)
        val layerBounds = android.graphics.RectF(0f, 0f, width.toFloat(), height.toFloat())
        canvas.saveLayer(layerBounds, null)

        // Draw dim glow effect for whole text (blur behind)
        glowPaint.alpha = (effectiveAlpha * 0.15f).toInt()
        canvas.drawText(text, scrollX + drawXOffset, drawY, glowPaint)

        // Draw each character individually with pre-calculated glitch effects
        var charX = scrollX + drawXOffset
        for (i in text.indices) {
            var char = text[i]

            // Apply case flip if this character is marked for it
            if (i < charCaseFlips.size && charCaseFlips[i] && char.isLetter()) {
                char = if (char.isUpperCase()) char.lowercaseChar() else char.uppercaseChar()
            }

            // Apply pre-calculated brightness variation for this character
            val charAlphaVariation = if (i < charGlitchAlphas.size) charGlitchAlphas[i] else 0
            val finalAlpha = (effectiveAlpha + charAlphaVariation).coerceIn(30, 255)  // Very wide range - dim chars nearly invisible

            textPaint.alpha = finalAlpha
            canvas.drawText(char.toString(), charX, drawY, textPaint)

            // Move to next character position (use original char for consistent spacing)
            textPaint.getTextWidths(text[i].toString(), charWidths)
            charX += charWidths[0]
        }

        // Draw scanlines only on text pixels using SRC_ATOP blend mode
        scanlinePaint.xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC_ATOP)
        for (y in 0 until height step scanlineSpacing) {
            val scanlineAlpha = if (y % 4 == 0) 0x50 else 0x30
            scanlinePaint.alpha = scanlineAlpha
            canvas.drawLine(0f, y.toFloat(), width.toFloat(), y.toFloat(), scanlinePaint)
        }
        scanlinePaint.xfermode = null

        // Restore the layer
        canvas.restore()

        // Occasional horizontal noise bar
        if (Random.nextInt(100) < 3) {
            val noiseY = Random.nextInt(height).toFloat()
            val noiseHeight = Random.nextInt(2, 5).toFloat()
            noisePaint.alpha = Random.nextInt(20, 60)
            canvas.drawRect(0f, noiseY, width.toFloat(), noiseY + noiseHeight, noisePaint)
        }

        // Update scroll position
        if (isScrolling) {
            val deltaTime = currentTime - lastFrameTime
            lastFrameTime = currentTime

            // Move text left
            scrollX -= scrollSpeed * (deltaTime / 16f)  // Normalize to ~60fps

            // Reset when text has scrolled completely off the left
            if (scrollX + textWidth < 0) {
                scrollX = width.toFloat()
            }

            // Request next frame
            postInvalidateOnAnimation()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (text.isNotEmpty()) {
            startScrolling()
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        stopScrolling()
    }
}
