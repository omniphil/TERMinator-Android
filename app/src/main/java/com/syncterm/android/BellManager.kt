package com.syncterm.android

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.media.RingtoneManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import java.util.concurrent.Executors
import kotlin.math.PI
import kotlin.math.sin

/**
 * Manages bell sounds and vibration for terminal BEL character.
 */
class BellManager(private val context: Context) {

    companion object {
        const val PREFS_NAME = "app_settings"
        const val KEY_SOUND_ENABLED = "sound_enabled"
        const val KEY_BELL_SOUND = "bell_sound"
        const val KEY_BELL_VOLUME = "bell_volume"
        const val KEY_VIBRATION_ENABLED = "vibration_enabled"

        // Bell sound types - sorted by year (oldest to newest)
        const val BELL_ALTAIR = 0       // 1975 - Altair 8800
        const val BELL_APPLE_II = 1     // 1977 - Apple II
        const val BELL_PET = 2          // 1977 - Commodore PET
        const val BELL_TRS80 = 3        // 1977 - TRS-80
        const val BELL_VT100 = 4        // 1978 - DEC VT100
        const val BELL_ATARI = 5        // 1979 - Atari 800
        const val BELL_APPLE_III = 6    // 1980 - Apple III
        const val BELL_VIC20 = 7        // 1980 - Commodore VIC-20
        const val BELL_COCO = 8         // 1980 - Tandy Color Computer
        const val BELL_IBM_PC = 9       // 1981 - IBM PC
        const val BELL_BBC_MICRO = 10   // 1981 - BBC Micro
        const val BELL_ZX81 = 11        // 1981 - Sinclair ZX81
        const val BELL_TI99 = 12        // 1981 - TI-99/4A
        const val BELL_OSBORNE = 13     // 1981 - Osborne 1
        const val BELL_C64 = 14         // 1982 - Commodore 64
        const val BELL_ZX_SPECTRUM = 15 // 1982 - ZX Spectrum
        const val BELL_KAYPRO = 16      // 1982 - Kaypro
        const val BELL_COLECO = 17      // 1982 - Colecovision
        const val BELL_NES = 18         // 1983 - NES/Famicom
        const val BELL_MSX = 19         // 1983 - MSX
        const val BELL_MAC_CLASSIC = 20 // 1984 - Macintosh
        const val BELL_AMSTRAD_CPC = 21 // 1984 - Amstrad CPC
        const val BELL_TANDY_1000 = 22  // 1984 - Tandy 1000
        const val BELL_PCJR = 23        // 1984 - IBM PCjr
        const val BELL_AMIGA = 24       // 1985 - Amiga
        const val BELL_ARCHIMEDES = 25  // 1987 - Acorn Archimedes
        const val BELL_NEXT = 26        // 1988 - NeXT Computer
        const val BELL_GAME_BOY = 27    // 1989 - Game Boy
        const val BELL_SUN = 28         // 1989 - Sun SPARCstation
        const val BELL_SYSTEM = 29      // System notification

        private const val SAMPLE_RATE = 44100
    }

    private var audioTrack: AudioTrack? = null
    private val vibrator: Vibrator
    // Single thread executor to prevent thread explosion from rapid bell sounds
    private val soundExecutor = Executors.newSingleThreadExecutor()

    init {
        vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vibratorManager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
            vibratorManager.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        }
    }

    /**
     * Play the bell sound and/or vibrate based on settings.
     */
    fun playBell() {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        if (prefs.getBoolean(KEY_SOUND_ENABLED, true)) {
            val soundType = prefs.getInt(KEY_BELL_SOUND, BELL_VT100)
            playSound(soundType)
        }

        if (prefs.getBoolean(KEY_VIBRATION_ENABLED, true)) {
            vibrate()
        }
    }

    /**
     * Play a specific bell sound.
     */
    fun playSound(soundType: Int) {
        when (soundType) {
            BELL_ALTAIR -> playAltairBell()              // 1975 - Altair 8800
            BELL_APPLE_II -> playAppleIIBell()           // 1977 - Apple II
            BELL_PET -> playPETBell()                    // 1977 - Commodore PET
            BELL_TRS80 -> playTRS80Bell()                // 1977 - TRS-80
            BELL_VT100 -> playVT100Bell()                // 1978 - DEC VT100
            BELL_ATARI -> playAtariBell()                // 1979 - Atari 800
            BELL_APPLE_III -> playAppleIIIBell()         // 1980 - Apple III
            BELL_VIC20 -> playVIC20Bell()                // 1980 - VIC-20
            BELL_COCO -> playCoCoBell()                  // 1980 - Color Computer
            BELL_IBM_PC -> playSquareWave(1000, 150)     // 1981 - IBM PC
            BELL_BBC_MICRO -> playBBCMicroBell()         // 1981 - BBC Micro
            BELL_ZX81 -> playZX81Bell()                  // 1981 - ZX81
            BELL_TI99 -> playTI99Bell()                  // 1981 - TI-99/4A
            BELL_OSBORNE -> playOsborneBell()            // 1981 - Osborne 1
            BELL_C64 -> playC64Bell()                    // 1982 - Commodore 64
            BELL_ZX_SPECTRUM -> playZXSpectrumBell()     // 1982 - ZX Spectrum
            BELL_KAYPRO -> playKayproBell()              // 1982 - Kaypro
            BELL_COLECO -> playColecoBell()              // 1982 - Colecovision
            BELL_NES -> playNESBell()                    // 1983 - NES/Famicom
            BELL_MSX -> playMSXBell()                    // 1983 - MSX
            BELL_MAC_CLASSIC -> playMacClassicBell()     // 1984 - Macintosh
            BELL_AMSTRAD_CPC -> playAmstradCPCBell()     // 1984 - Amstrad CPC
            BELL_TANDY_1000 -> playTandy1000Bell()       // 1984 - Tandy 1000
            BELL_PCJR -> playPCjrBell()                  // 1984 - IBM PCjr
            BELL_AMIGA -> playAmigaBell()                // 1985 - Amiga
            BELL_ARCHIMEDES -> playArchimedesBell()      // 1987 - Archimedes
            BELL_NEXT -> playNeXTBell()                  // 1988 - NeXT
            BELL_GAME_BOY -> playGameBoyBell()           // 1989 - Game Boy
            BELL_SUN -> playSunBell()                    // 1989 - Sun SPARCstation
            BELL_SYSTEM -> playSystemNotification()
            else -> playSystemNotification()  // Fallback for unknown sound types
        }
    }

    /**
     * Generate and play a square wave (IBM PC speaker sound).
     * IBM PC BIOS typically uses ~1000Hz for the standard beep.
     * The 8253/8254 timer is clocked at 1,193,180 Hz.
     */
    private fun playSquareWave(frequency: Int, durationMs: Int) {
        soundExecutor.execute {
            try {
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                // Generate square wave with fade envelope
                val fadeLength = minOf(numSamples / 10, 500)
                for (i in 0 until numSamples) {
                    // Square wave: +1 or -1 based on position in period
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Apply fade envelope to avoid clicks
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.3).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Apple II bell - 1kHz square wave via 1-bit speaker toggle.
     * The Apple II ROM bell routine at $FBDD produces a ~1000Hz tone.
     */
    private fun playAppleIIBell() {
        soundExecutor.execute {
            try {
                val durationMs = 100
                val frequency = 1000  // Documented Apple II bell frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                val fadeLength = numSamples / 10
                for (i in 0 until numSamples) {
                    // Square wave (Apple II was 1-bit speaker toggle)
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Commodore 64/128 SID bell - triangle waveform at ~750Hz.
     * Based on actual C128 KERNAL code: $D401=$30 (freq hi), Attack=0, Decay=9.
     * SID frequency formula: f = (Fclk * $3000) / 16777216 ≈ 750Hz
     */
    private fun playC64Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 200
                val frequency = 750  // Actual C64/C128 bell frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)

                // C128 uses Attack=0 (instant), Decay=9 (~750ms decay)
                // Simplified ADSR: instant attack, medium decay, no sustain
                val decayStart = numSamples / 20  // Very short attack
                for (i in 0 until numSamples) {
                    // Triangle waveform (C128 bell uses triangle, not pulse)
                    val phase = (i * frequency.toDouble() / SAMPLE_RATE) % 1.0
                    var amplitude = if (phase < 0.5) 4 * phase - 1 else 3 - 4 * phase

                    // SID ADSR envelope: instant attack, decay to silence
                    if (i < decayStart) {
                        amplitude *= i.toDouble() / decayStart
                    } else {
                        // Decay curve (SID decay is roughly exponential)
                        val decayProgress = (i - decayStart).toDouble() / (numSamples - decayStart)
                        amplitude *= (1.0 - decayProgress) * (1.0 - decayProgress)
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.7).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Atari 800 POKEY bell - ~960Hz square wave.
     * The characteristic Atari beep during disk I/O is derived from
     * the interrupt timer frequency (half of 19200 baud = ~960Hz).
     */
    private fun playAtariBell() {
        soundExecutor.execute {
            try {
                val durationMs = 120
                val frequency = 960  // Documented Atari I/O beep frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                val fadeLength = minOf(numSamples / 10, 300)
                for (i in 0 until numSamples) {
                    // POKEY produces square waves
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * BBC Micro bell (VDU 7) - Descending frequency sweep via SN76489.
     * The BBC Micro's distinctive "chirp" sweeps from high to low frequency.
     */
    private fun playBBCMicroBell() {
        soundExecutor.execute {
            try {
                val durationMs = 200
                val startFreq = 2000.0  // Start high
                val endFreq = 800.0     // End lower
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 10
                var phase = 0.0

                for (i in 0 until numSamples) {
                    val progress = i.toDouble() / numSamples
                    val frequency = startFreq + (endFreq - startFreq) * progress

                    phase += 2.0 * PI * frequency / SAMPLE_RATE
                    var amplitude = sin(phase)

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * DEC VT100 terminal bell - the canonical terminal bell sound.
     * ~800Hz tone as documented in FreeBSD vt implementation.
     */
    private fun playVT100Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 100
                val frequency = 800  // Documented VT100 frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)

                val attackLength = numSamples / 20
                val decayStart = numSamples / 3
                for (i in 0 until numSamples) {
                    val angle = 2.0 * PI * i * frequency / SAMPLE_RATE
                    var amplitude = sin(angle)

                    // Sharp attack, longer decay (characteristic of real terminal bells)
                    when {
                        i < attackLength -> amplitude *= i.toDouble() / attackLength
                        i > decayStart -> {
                            val decayProgress = (i - decayStart).toDouble() / (numSamples - decayStart)
                            amplitude *= (1.0 - decayProgress * decayProgress)  // Exponential-ish decay
                        }
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.75).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * TRS-80 Model I/III bell - sound via cassette port.
     * The TRS-80 had no built-in speaker; sound was output through
     * the cassette port. Adding slight wobble to simulate the analog path.
     */
    private fun playTRS80Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 120
                val baseFreq = 450.0  // Lower base frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 10

                for (i in 0 until numSamples) {
                    // Add wobble to simulate cassette port analog character
                    val wobble = 1.0 + 0.02 * sin(2.0 * PI * i * 30.0 / SAMPLE_RATE)
                    val frequency = baseFreq * wobble
                    val period = maxOf((SAMPLE_RATE / frequency).toInt(), 1)

                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.55).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * ZX Spectrum beeper bell - Descending frequency sweep.
     * The Spectrum's characteristic "chirp" sound from high to low.
     */
    private fun playZXSpectrumBell() {
        soundExecutor.execute {
            try {
                val durationMs = 150
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 12
                var phase = 0.0

                for (i in 0 until numSamples) {
                    val progress = i.toDouble() / numSamples

                    // Frequency sweep: starts high, drops quickly, then settles
                    val frequency = when {
                        progress < 0.1 -> 2400.0 - (progress / 0.1) * 1400.0
                        progress < 0.3 -> 1000.0 - ((progress - 0.1) / 0.2) * 200.0
                        else -> 800.0
                    }

                    phase += 2.0 * PI * frequency / SAMPLE_RATE

                    // Square wave (1-bit beeper)
                    var amplitude = if (sin(phase) > 0) 1.0 else -1.0

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Amiga Workbench beep - Paula plays 8-bit samples.
     * The Amiga doesn't have a tone generator; beeps are short waveform samples
     * played through the 4-channel 8-bit Paula chip. ~880Hz (A5) is common.
     */
    private fun playAmigaBell() {
        soundExecutor.execute {
            try {
                val durationMs = 100
                val frequency = 880  // A5 - common Amiga alert frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)

                val fadeLength = numSamples / 10
                for (i in 0 until numSamples) {
                    val angle = 2.0 * PI * i * frequency / SAMPLE_RATE

                    // Paula plays samples - typically sine or simple waveforms
                    var amplitude = sin(angle)

                    // Quantize to 8-bit (Paula was 8-bit DAC)
                    amplitude = (amplitude * 127).toInt() / 127.0

                    // Simple envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.7).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Original Macintosh (1984) startup/alert beep - 600Hz square wave.
     * Programmed by Andy Hertzfeld using the MOS 6522 VIA chip.
     */
    private fun playMacClassicBell() {
        soundExecutor.execute {
            try {
                val durationMs = 150
                val frequency = 600  // Documented original Mac beep frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                val fadeLength = numSamples / 15
                for (i in 0 until numSamples) {
                    // Original Mac used square wave via 6522 VIA
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Quick attack, sustain, then decay
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength * 2) {
                        amplitude *= (numSamples - i).toDouble() / (fadeLength * 2)
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Amstrad CPC bell - AY-3-8912 PSG chip with 3-note arpeggio.
     * The CPC's AY chip was often used for quick arpeggiated sounds.
     */
    private fun playAmstradCPCBell() {
        soundExecutor.execute {
            try {
                val noteMs = 50
                val notes = intArrayOf(880, 1109, 1319)  // Ascending arpeggio
                val samplesPerNote = (SAMPLE_RATE * noteMs / 1000.0).toInt()
                val totalSamples = samplesPerNote * notes.size
                val samples = ShortArray(totalSamples)

                for ((noteIdx, freq) in notes.withIndex()) {
                    val period = SAMPLE_RATE / freq
                    val noteStart = noteIdx * samplesPerNote

                    for (i in 0 until samplesPerNote) {
                        var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                        // Per-note envelope
                        val noteProgress = i.toDouble() / samplesPerNote
                        if (noteProgress < 0.1) {
                            amplitude *= noteProgress / 0.1
                        } else if (noteProgress > 0.8) {
                            amplitude *= (1.0 - noteProgress) / 0.2
                        }

                        samples[noteStart + i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                    }
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Commodore PET bell (CHR$(7)) - piezo speaker via 6522 VIA shift register.
     * The 4000/8000 series PETs have a built-in piezo that "chirps" on reset.
     * Short, clicky sound around 1000Hz.
     */
    private fun playPETBell() {
        soundExecutor.execute {
            try {
                val durationMs = 50  // Short click
                val frequency = 1000
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                for (i in 0 until numSamples) {
                    // Square wave (1-bit output)
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Quick decay (piezo character)
                    val progress = i.toDouble() / numSamples
                    amplitude *= (1.0 - progress)

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Tandy 1000 bell - SN76489 PSG 3-voice chord.
     * The Tandy 1000's PSG could play 3 simultaneous square waves.
     */
    private fun playTandy1000Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 140
                val freq1 = 523  // C5
                val freq2 = 659  // E5
                val freq3 = 784  // G5
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 8

                val period1 = SAMPLE_RATE / freq1
                val period2 = SAMPLE_RATE / freq2
                val period3 = SAMPLE_RATE / freq3

                for (i in 0 until numSamples) {
                    val wave1 = if ((i % period1) < (period1 / 2)) 1.0 else -1.0
                    val wave2 = if ((i % period2) < (period2 / 2)) 1.0 else -1.0
                    val wave3 = if ((i % period3) < (period3 / 2)) 1.0 else -1.0

                    var amplitude = (wave1 + wave2 * 0.8 + wave3 * 0.6) / 2.4

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength * 2) {
                        amplitude *= (numSamples - i).toDouble() / (fadeLength * 2)
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.45).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Texas Instruments TI-99/4A bell - TMS9919 PSG with vibrato.
     * The TI-99's distinctive sound often featured slight pitch modulation.
     */
    private fun playTI99Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 200
                val baseFreq = 660.0  // Unique base frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 10

                for (i in 0 until numSamples) {
                    // Add vibrato effect
                    val vibratoRate = 25.0
                    val vibratoDepth = 0.03
                    val vibrato = 1.0 + vibratoDepth * sin(2.0 * PI * i * vibratoRate / SAMPLE_RATE)
                    val frequency = baseFreq * vibrato
                    val period = maxOf((SAMPLE_RATE / frequency).toInt(), 1)

                    // Two-voice harmony
                    val freq2 = baseFreq * 1.5 * vibrato
                    val period2 = maxOf((SAMPLE_RATE / freq2).toInt(), 1)

                    val wave1 = if ((i % period) < (period / 2)) 1.0 else -1.0
                    val wave2 = if ((i % period2) < (period2 / 2)) 1.0 else -1.0
                    var amplitude = wave1 * 0.6 + wave2 * 0.4

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * NeXT Computer bell - high-quality FM synthesis.
     * The NeXT's DSP enabled sophisticated sound; using FM for a rich bell.
     */
    private fun playNeXTBell() {
        soundExecutor.execute {
            try {
                val durationMs = 250
                val carrierFreq = 587.0  // D5
                val modulatorFreq = carrierFreq * 2
                val modulationIndex = 0.3
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)

                val attackLength = numSamples / 20
                val sustainEnd = numSamples / 2

                for (i in 0 until numSamples) {
                    // FM synthesis
                    val modulator = sin(2.0 * PI * i * modulatorFreq / SAMPLE_RATE)
                    val carrier = sin(2.0 * PI * i * carrierFreq / SAMPLE_RATE + modulationIndex * modulator)
                    val sub = sin(2.0 * PI * i * (carrierFreq / 2) / SAMPLE_RATE)

                    var amplitude = carrier * 0.8 + sub * 0.2

                    // ADSR envelope
                    if (i < attackLength) {
                        val attackCurve = i.toDouble() / attackLength
                        amplitude *= attackCurve * attackCurve
                    } else if (i > sustainEnd) {
                        val releaseProgress = (i - sustainEnd).toDouble() / (numSamples - sustainEnd)
                        amplitude *= (1.0 - releaseProgress) * (1.0 - releaseProgress)
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Nintendo Game Boy bell - pulse channel with duty cycle sweep.
     * The DMG's pulse channels could sweep through duty cycles for unique timbres.
     */
    private fun playGameBoyBell() {
        soundExecutor.execute {
            try {
                val durationMs = 120
                val frequency = 880.0  // A5
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                for (i in 0 until numSamples) {
                    val progress = i.toDouble() / numSamples

                    // Sweep duty cycle from 12.5% to 50%
                    val dutyCycle = 0.125 + progress * 0.375
                    val posInPeriod = (i % period.toInt()).toDouble() / period

                    var amplitude = if (posInPeriod < dutyCycle) 1.0 else -1.0

                    // GB-style volume envelope (linear decay)
                    amplitude *= maxOf(0.0, 1.0 - progress * 1.5)

                    // 4-bit quantization
                    amplitude = ((amplitude * 7.5).toInt() / 7.5)

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Nintendo NES/Famicom bell - 2A03 APU triangle + pulse combo.
     * Using the characteristic NES triangle wave with pulse overlay.
     */
    private fun playNESBell() {
        soundExecutor.execute {
            try {
                val durationMs = 150
                val pulseFreq = 440.0  // A4
                val triFreq = 220.0    // A3 (octave below)
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 8

                for (i in 0 until numSamples) {
                    // Triangle wave (4-bit quantized like real NES)
                    val triPhase = (i * triFreq / SAMPLE_RATE) % 1.0
                    var triValue = if (triPhase < 0.5) 4 * triPhase - 1 else 3 - 4 * triPhase
                    triValue = ((triValue * 7.5).toInt() / 7.5)  // 4-bit

                    // 25% duty pulse
                    val pulsePhase = (i * pulseFreq / SAMPLE_RATE) % 1.0
                    val pulse = if (pulsePhase < 0.25) 1.0 else -1.0

                    var amplitude = triValue * 0.6 + pulse * 0.4

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.55).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Acorn Archimedes bell - VIDC rich harmonic sample.
     * The Archimedes had sophisticated audio; using additive synthesis.
     */
    private fun playArchimedesBell() {
        soundExecutor.execute {
            try {
                val durationMs = 180
                val baseFreq = 523.0  // C5
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)

                val attackEnd = numSamples / 10
                val sustainEnd = numSamples * 2 / 3

                for (i in 0 until numSamples) {
                    val phase = (i * baseFreq / SAMPLE_RATE) % 1.0

                    // Additive synthesis for bell-like timbre
                    var amplitude = sin(2.0 * PI * phase) * 0.5 +
                                   sin(4.0 * PI * phase) * 0.25 +
                                   sin(6.0 * PI * phase) * 0.15 +
                                   sin(8.0 * PI * phase) * 0.1

                    // Slight pitch bend at start for attack transient
                    val pitchEnv = 1.0 + 0.02 * kotlin.math.exp(-i.toDouble() * 10.0 / numSamples)
                    val phase2 = (i * baseFreq * pitchEnv / SAMPLE_RATE) % 1.0
                    amplitude = amplitude * 0.7 + sin(2.0 * PI * phase2) * 0.3

                    // ADSR envelope
                    if (i < attackEnd) {
                        amplitude *= i.toDouble() / attackEnd
                    } else if (i > sustainEnd) {
                        val release = (i - sustainEnd).toDouble() / (numSamples - sustainEnd)
                        amplitude *= 1.0 - release * release
                    }

                    // 8-bit quantization
                    amplitude = ((amplitude * 127).toInt() / 127.0)

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Sun SPARCstation console bell - 440Hz (A4) sine wave.
     * Unix workstations traditionally use 440Hz for the console bell.
     * Sun had quality audio hardware producing clean tones.
     */
    private fun playSunBell() {
        soundExecutor.execute {
            try {
                val durationMs = 100
                val frequency = 440  // A4 - standard Unix console bell
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)

                val fadeLength = numSamples / 15
                for (i in 0 until numSamples) {
                    val angle = 2.0 * PI * i * frequency / SAMPLE_RATE

                    // Clean sine wave
                    var amplitude = sin(angle)

                    // Simple envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.7).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * MSX bell - AY-3-8910 PSG chip with two-note sequence.
     * The MSX often used quick high-low note sequences for alerts.
     */
    private fun playMSXBell() {
        soundExecutor.execute {
            try {
                val note1Ms = 60
                val note2Ms = 80
                val freq1 = 1047  // C6 (high)
                val freq2 = 784   // G5 (lower)
                val note1Samples = (SAMPLE_RATE * note1Ms / 1000.0).toInt()
                val totalSamples = note1Samples + (SAMPLE_RATE * note2Ms / 1000.0).toInt()
                val samples = ShortArray(totalSamples)

                for (i in 0 until totalSamples) {
                    val freq = if (i < note1Samples) freq1 else freq2
                    val noteStart = if (i < note1Samples) 0 else note1Samples
                    val noteLen = if (i < note1Samples) note1Samples else totalSamples - note1Samples
                    val notePos = i - noteStart
                    val period = SAMPLE_RATE / freq

                    var amplitude = if ((notePos % period) < (period / 2)) 1.0 else -1.0

                    // Per-note envelope
                    val noteProgress = notePos.toDouble() / noteLen
                    if (noteProgress < 0.05) {
                        amplitude *= noteProgress / 0.05
                    } else if (noteProgress > 0.7) {
                        amplitude *= (1.0 - noteProgress) / 0.3
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Osborne 1 bell (1981) - piezo beeper at high frequency.
     * The piezo speaker produced a higher, thinner sound.
     */
    private fun playOsborneBell() {
        soundExecutor.execute {
            try {
                val durationMs = 80
                val frequency = 2000  // Higher piezo frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                for (i in 0 until numSamples) {
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Add slight ring modulation for piezo character
                    val ring = sin(2.0 * PI * i * 4000.0 / SAMPLE_RATE) * 0.15
                    amplitude = amplitude * 0.85 + ring

                    // Quick decay (piezo character)
                    val progress = i.toDouble() / numSamples
                    amplitude *= 1.0 - progress * progress

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Altair 8800 (1975) - No speaker hardware.
     * The Altair had no audio output. Users would place an AM radio nearby
     * to hear RF interference from the CPU bus. We simulate the scratchy,
     * warbling radio sound with multiple modulating frequencies.
     */
    private fun playAltairBell() {
        soundExecutor.execute {
            try {
                val durationMs = 200
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                var phase = 0.0
                val fadeLength = numSamples / 10

                for (i in 0 until numSamples) {
                    // Multiple wobbling frequencies to simulate RF interference
                    val freq1 = 800.0 + (i % 100) * 5  // Warbling base
                    val freq2 = 1200.0 + (i % 73) * 7  // Higher harmonic
                    val freq3 = 400.0 + (i % 150) * 3  // Lower undertone

                    phase += 2.0 * PI / SAMPLE_RATE
                    var amplitude = sin(phase * freq1) * 0.4 +
                                   sin(phase * freq2) * 0.3 +
                                   sin(phase * freq3) * 0.3

                    // Add some "static" crackle effect
                    if (i % 44 < 22) amplitude *= 0.8

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Commodore VIC-20 (1980) - 6560/6561 VIC chip with two voices.
     * The VIC chip had 3 square wave voices; using 2 for a richer sound.
     */
    private fun playVIC20Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 150
                val freq1 = 523  // C5
                val freq2 = 659  // E5
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 8

                val period1 = SAMPLE_RATE / freq1
                val period2 = SAMPLE_RATE / freq2

                for (i in 0 until numSamples) {
                    val wave1 = if ((i % period1) < (period1 / 2)) 1.0 else -1.0
                    val wave2 = if ((i % period2) < (period2 / 2)) 1.0 else -1.0

                    var amplitude = wave1 * 0.6 + wave2 * 0.4

                    // 4-bit quantization for VIC character
                    amplitude = ((amplitude * 8).toInt() / 8.0)

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.55).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Sinclair ZX81 (1981) - 1-bit beeper via ULA chip.
     * Short, sharp beep at 900Hz with quick decay - the ZX81's characteristic click.
     */
    private fun playZX81Bell() {
        soundExecutor.execute {
            try {
                val durationMs = 60  // Very short
                val frequency = 900  // Higher, more distinctive
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency

                for (i in 0 until numSamples) {
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Quick decay (no sustain)
                    val progress = i.toDouble() / numSamples
                    amplitude *= 1.0 - progress * 0.5

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Tandy Color Computer "CoCo" (1980) - 6-bit DAC audio.
     * The CoCo's DAC produced warmer tones; using sine with harmonics.
     */
    private fun playCoCoBell() {
        soundExecutor.execute {
            try {
                val durationMs = 130
                val frequency = 660.0  // Unique frequency
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 10

                for (i in 0 until numSamples) {
                    val angle = 2.0 * PI * i * frequency / SAMPLE_RATE

                    // Sine with harmonics for DAC character
                    var amplitude = sin(angle) * 0.7 + sin(angle * 2) * 0.2 + sin(angle * 3) * 0.1

                    // 6-bit quantization
                    amplitude = ((amplitude * 32).toInt() / 32.0)

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Apple III (1980) - 6-bit DAC via 6522 VIA chip.
     * Smoother sound than Apple II with sine wave and third harmonic.
     */
    private fun playAppleIIIBell() {
        soundExecutor.execute {
            try {
                val durationMs = 140
                val frequency = 770.0  // Slightly different from Apple II
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 12

                for (i in 0 until numSamples) {
                    val angle = 2.0 * PI * i * frequency / SAMPLE_RATE

                    // Sine with third harmonic for richer sound
                    var amplitude = sin(angle) * 0.8 + sin(angle * 3) * 0.2

                    // 6-bit quantization
                    amplitude = ((amplitude * 32).toInt() / 32.0)

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.6).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Kaypro (1982) - piezo beeper, CP/M portable computer.
     * 800Hz square wave - the Kaypro had a lower, businesslike beep.
     */
    private fun playKayproBell() {
        soundExecutor.execute {
            try {
                val durationMs = 100
                val frequency = 800  // Lower, more business-like
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val period = SAMPLE_RATE / frequency
                val fadeLength = numSamples / 15

                for (i in 0 until numSamples) {
                    var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Colecovision (1982) - Texas Instruments SN76489 PSG.
     * Descending 3-note arpeggio characteristic of game console alerts.
     */
    private fun playColecoBell() {
        soundExecutor.execute {
            try {
                val durationMs = 120
                val freqs = intArrayOf(1047, 880, 698)  // Descending C6-A5-F5
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samplesPerNote = numSamples / freqs.size
                val samples = ShortArray(numSamples)

                for ((noteIdx, freq) in freqs.withIndex()) {
                    val period = SAMPLE_RATE / freq
                    val noteStart = noteIdx * samplesPerNote

                    for (i in 0 until samplesPerNote) {
                        var amplitude = if ((i % period) < (period / 2)) 1.0 else -1.0

                        // Per-note envelope
                        val progress = i.toDouble() / samplesPerNote
                        if (progress < 0.1) {
                            amplitude *= progress / 0.1
                        } else if (progress > 0.7) {
                            amplitude *= (1.0 - progress) / 0.3
                        }

                        samples[noteStart + i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                    }
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * IBM PCjr (1984) - SN76496 PSG two-voice harmony.
     * The PCjr could play multiple voices; using octave harmony.
     */
    private fun playPCjrBell() {
        soundExecutor.execute {
            try {
                val durationMs = 150
                val freq1 = 440  // A4
                val freq2 = 880  // A5 (octave above)
                val numSamples = (SAMPLE_RATE * durationMs / 1000.0).toInt()
                val samples = ShortArray(numSamples)
                val fadeLength = numSamples / 10

                val period1 = SAMPLE_RATE / freq1
                val period2 = SAMPLE_RATE / freq2

                for (i in 0 until numSamples) {
                    val wave1 = if ((i % period1) < (period1 / 2)) 1.0 else -1.0
                    val wave2 = if ((i % period2) < (period2 / 2)) 1.0 else -1.0

                    var amplitude = wave1 * 0.7 + wave2 * 0.3

                    // Envelope
                    if (i < fadeLength) {
                        amplitude *= i.toDouble() / fadeLength
                    } else if (i > numSamples - fadeLength) {
                        amplitude *= (numSamples - i).toDouble() / fadeLength
                    }

                    samples[i] = (amplitude * Short.MAX_VALUE * 0.5).toInt().toShort()
                }

                playGeneratedSamples(samples)
            } catch (e: Exception) {
                playSystemNotification()
            }
        }
    }

    /**
     * Get the current volume setting (0.0 to 1.0).
     */
    private fun getVolume(): Float {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val volumeLevel = prefs.getInt(KEY_BELL_VOLUME, 5) // Default 50%
        return volumeLevel / 10.0f
    }

    /**
     * Helper to play pre-generated samples.
     */
    @Synchronized
    private fun playGeneratedSamples(samples: ShortArray) {
        try {
            // Apply volume scaling
            val volume = getVolume()
            val scaledSamples = if (volume < 1.0f) {
                ShortArray(samples.size) { i ->
                    (samples[i] * volume).toInt().toShort()
                }
            } else {
                samples
            }

            val bufferSize = AudioTrack.getMinBufferSize(
                SAMPLE_RATE,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )

            // Release previous track before creating new one
            // Use try-finally to ensure proper cleanup even if stop() throws
            val oldTrack = audioTrack
            if (oldTrack != null) {
                audioTrack = null
                try {
                    oldTrack.stop()
                } catch (e: Exception) {
                    // Ignore stop errors (track may already be stopped)
                } finally {
                    try {
                        oldTrack.release()
                    } catch (e: Exception) {
                        // Ignore release errors
                    }
                }
            }

            val newTrack = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .setSampleRate(SAMPLE_RATE)
                        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .build()
                )
                .setBufferSizeInBytes(maxOf(bufferSize, scaledSamples.size * 2))
                .setTransferMode(AudioTrack.MODE_STATIC)
                .build()

            newTrack.write(scaledSamples, 0, scaledSamples.size)
            newTrack.play()
            audioTrack = newTrack
        } catch (e: Exception) {
            // Log but don't crash if audio playback fails
            android.util.Log.e("BellManager", "Failed to play samples: ${e.message}")
        }
    }

    /**
     * Play system notification sound.
     */
    private fun playSystemNotification() {
        try {
            val notification = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
            RingtoneManager.getRingtone(context, notification)?.play()
        } catch (e: Exception) {
            // Ignore if notification sound fails
        }
    }

    /**
     * Vibrate the device briefly.
     */
    fun vibrate() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createOneShot(100, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(100)
            }
        } catch (e: Exception) {
            // Ignore if vibration fails
        }
    }

    /**
     * Release resources.
     */
    fun release() {
        soundExecutor.shutdownNow()
        audioTrack?.release()
        audioTrack = null
    }
}
