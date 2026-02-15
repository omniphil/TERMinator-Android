package com.syncterm.android

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ObjectAnimator
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.util.AttributeSet
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.TextView
import androidx.core.content.res.ResourcesCompat

/**
 * Vertical scrolling ticker that displays retro computing history facts.
 * Shows 2 lines at a time, scrolling upward.
 */
class HistoryTickerView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : FrameLayout(context, attrs, defStyleAttr) {

    private val facts: Array<String> by lazy {
        context.resources.getStringArray(R.array.computing_history_facts)
    }

    // Shuffled list of indices to ensure no repeats until all facts shown
    private var shuffledIndices: MutableList<Int> = mutableListOf()
    private var currentPosition = 0

    private val currentText: TextView
    private val nextText: TextView

    private var isScrolling = false
    private var scrollRunnable: Runnable? = null

    private val displayDuration = 8000L  // Show each fact for 8 seconds
    private val scrollDuration = 1000L   // Scroll animation takes 1 second

    // Load retro font
    private val retroFont: Typeface? = try {
        ResourcesCompat.getFont(context, R.font.press_start_2p)
    } catch (e: Exception) {
        null
    }

    // Track if animation is in progress to prevent rapid tapping issues
    private var isAnimating = false

    init {
        clipChildren = true
        clipToPadding = true

        // Create two TextViews for the scrolling effect
        currentText = createTextView()
        nextText = createTextView()

        addView(currentText)
        addView(nextText)

        // Position nextText below the visible area initially
        nextText.visibility = View.INVISIBLE

        // Allow tap to advance to next fact
        isClickable = true
        isFocusable = true
        setOnClickListener {
            skipToNext()
        }
    }

    /**
     * Skip to the next fact immediately when user taps.
     */
    fun skipToNext() {
        if (!isScrolling || isAnimating) return

        // Cancel the scheduled auto-scroll
        scrollRunnable?.let { removeCallbacks(it) }

        // Trigger the scroll immediately
        scrollToNext()
    }

    private fun createTextView(): TextView {
        return TextView(context).apply {
            layoutParams = LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT)
            setTextColor(Color.parseColor("#55DD55"))  // Match marquee green
            textSize = 11f  // 25% smaller
            typeface = retroFont ?: Typeface.MONOSPACE
            gravity = Gravity.CENTER
            maxLines = 2
            isSingleLine = false
            ellipsize = null
            setPadding(16, 4, 16, 4)
        }
    }

    fun startScrolling() {
        if (facts.isEmpty()) return

        isScrolling = true

        // Shuffle the indices to randomize order without repeats
        shuffleIndices()
        currentPosition = 0

        currentText.text = facts[shuffledIndices[currentPosition]]
        currentText.translationY = 0f
        currentText.alpha = 1f

        scheduleNextScroll()
    }

    /**
     * Shuffle all fact indices. Called when starting or when we've shown all facts.
     */
    private fun shuffleIndices() {
        shuffledIndices = facts.indices.toMutableList()
        shuffledIndices.shuffle()
    }

    fun stopScrolling() {
        isScrolling = false
        scrollRunnable?.let { removeCallbacks(it) }
    }

    private fun scheduleNextScroll() {
        scrollRunnable = Runnable {
            if (isScrolling) {
                scrollToNext()
            }
        }
        postDelayed(scrollRunnable!!, displayDuration)
    }

    private fun scrollToNext() {
        if (!isScrolling || isAnimating) return

        isAnimating = true

        // Move to next position, reshuffle if we've shown all facts
        currentPosition++
        if (currentPosition >= shuffledIndices.size) {
            shuffleIndices()
            currentPosition = 0
        }

        // Prepare next text
        nextText.text = facts[shuffledIndices[currentPosition]]
        nextText.translationY = height.toFloat()
        nextText.alpha = 1f
        nextText.visibility = View.VISIBLE

        // Animate current text upward and fade out
        val currentAnimator = ObjectAnimator.ofFloat(currentText, "translationY", 0f, -height.toFloat())
        currentAnimator.duration = scrollDuration

        val currentFadeAnimator = ObjectAnimator.ofFloat(currentText, "alpha", 1f, 0f)
        currentFadeAnimator.duration = scrollDuration

        // Animate next text upward into view
        val nextAnimator = ObjectAnimator.ofFloat(nextText, "translationY", height.toFloat(), 0f)
        nextAnimator.duration = scrollDuration

        nextAnimator.addListener(object : AnimatorListenerAdapter() {
            override fun onAnimationEnd(animation: Animator) {
                // Swap references
                currentText.text = nextText.text
                currentText.translationY = 0f
                currentText.alpha = 1f

                nextText.visibility = View.INVISIBLE
                isAnimating = false

                // Schedule next scroll
                if (isScrolling) {
                    scheduleNextScroll()
                }
            }
        })

        currentAnimator.start()
        currentFadeAnimator.start()
        nextAnimator.start()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (facts.isNotEmpty()) {
            startScrolling()
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        stopScrolling()
    }
}
