package com.syncterm.android

import android.content.Context
import android.graphics.Canvas
import android.util.AttributeSet
import androidx.appcompat.widget.AppCompatImageView
import kotlin.random.Random

/**
 * Custom ImageView that periodically applies a glitch effect.
 * Randomly shifts horizontal strips of the image left/right to create
 * an unstable, "glitch in the matrix" appearance.
 */
class GlitchImageView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : AppCompatImageView(context, attrs, defStyleAttr) {

    // Glitch parameters
    private var isGlitching = false
    private var glitchStrips = mutableListOf<GlitchStrip>()
    private var glitchFrameCount = 0
    private var totalGlitchFrames = 0

    // Timing
    private var glitchEnabled = false
    private val glitchRunnable = Runnable { startGlitch() }

    data class GlitchStrip(
        val yPercent: Float,      // Y position as percentage of view height (0-1)
        val heightPercent: Float, // Height as percentage of view height
        val offsetX: Int,         // Horizontal offset in pixels
        val frameStart: Int,      // Frame when this strip starts glitching
        val frameEnd: Int         // Frame when this strip stops glitching
    )

    /**
     * Enable the glitch effect with random timing.
     */
    fun enableGlitch() {
        glitchEnabled = true
        scheduleNextGlitch()
    }

    /**
     * Disable the glitch effect.
     */
    fun disableGlitch() {
        glitchEnabled = false
        handler?.removeCallbacks(glitchRunnable)
        isGlitching = false
        glitchStrips.clear()
        invalidate()
    }

    /**
     * Schedule the next glitch to occur in 3-7 seconds.
     */
    private fun scheduleNextGlitch() {
        if (!glitchEnabled) return
        handler?.removeCallbacks(glitchRunnable)
        val delay = (3000 + Random.nextInt(4000)).toLong()  // 3-7 seconds (more frequent)
        handler?.postDelayed(glitchRunnable, delay)
    }

    /**
     * Start a glitch effect.
     */
    private fun startGlitch() {
        if (!glitchEnabled || width == 0 || height == 0) {
            scheduleNextGlitch()
            return
        }

        isGlitching = true
        glitchFrameCount = 0
        totalGlitchFrames = 12 + Random.nextInt(12)  // 12-24 frames (~200-400ms at 60fps, longer duration)

        // Generate random glitch strips
        glitchStrips.clear()
        val numStrips = 6 + Random.nextInt(8)  // 6-13 strips (more strips)

        for (i in 0 until numStrips) {
            val yPercent = Random.nextFloat() * 0.9f  // 0-90% from top
            val heightPercent = 0.02f + Random.nextFloat() * 0.06f  // 2-8% of height (taller strips)
            val offsetX = (Random.nextInt(120) - 60)  // -60 to +60 pixels (more displacement)
            val frameStart = Random.nextInt(totalGlitchFrames / 2)
            val frameEnd = frameStart + 3 + Random.nextInt(totalGlitchFrames / 2)

            glitchStrips.add(GlitchStrip(
                yPercent,
                heightPercent,
                offsetX,
                frameStart,
                frameEnd.coerceAtMost(totalGlitchFrames)
            ))
        }

        // Start animation
        animateGlitch()
    }

    /**
     * Animate through glitch frames.
     */
    private fun animateGlitch() {
        if (!isGlitching) return

        invalidate()
        glitchFrameCount++

        if (glitchFrameCount < totalGlitchFrames) {
            // Continue animation (~16ms per frame for 60fps)
            postDelayed({ animateGlitch() }, 16)
        } else {
            // Glitch complete
            isGlitching = false
            glitchStrips.clear()
            invalidate()
            scheduleNextGlitch()
        }
    }

    override fun onDraw(canvas: Canvas) {
        if (!isGlitching || glitchStrips.isEmpty()) {
            super.onDraw(canvas)
            return
        }

        // Draw the base image first
        super.onDraw(canvas)

        // Now draw glitched strips on top
        for (strip in glitchStrips) {
            // Check if this strip is active in current frame
            val isActive = glitchFrameCount >= strip.frameStart && glitchFrameCount < strip.frameEnd
            if (!isActive) continue

            val stripY = (strip.yPercent * height).toInt()
            val stripHeight = (strip.heightPercent * height).toInt().coerceAtLeast(4)

            // Save canvas state
            canvas.save()

            // Clip to just this strip area
            canvas.clipRect(0, stripY, width, stripY + stripHeight)

            // Translate horizontally for the glitch offset
            canvas.translate(strip.offsetX.toFloat(), 0f)

            // Draw the image again (only the clipped strip will show, offset)
            super.onDraw(canvas)

            // Restore canvas state
            canvas.restore()
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        disableGlitch()
    }
}
