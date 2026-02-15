package com.syncterm.android

import android.app.Activity
import android.content.Intent
import android.content.pm.ActivityInfo
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.syncterm.android.databinding.ActivitySettingsBinding

/**
 * Settings activity for app-wide configuration.
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private lateinit var bellManager: BellManager

    // Settings keys
    companion object {
        const val PREFS_NAME = "app_settings"
        const val KEY_SOUND_ENABLED = "sound_enabled"
        const val KEY_BELL_SOUND = "bell_sound"
        const val KEY_BELL_VOLUME = "bell_volume"
        const val KEY_VIBRATION_ENABLED = "vibration_enabled"
        const val KEY_ORIENTATION = "orientation"
        // Bell sound indices - sorted by year (oldest to newest)
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
    }

    // Activity result launchers
    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        uri?.let { exportConnectionsTo(it) }
    }

    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { importConnectionsFrom(it) }
    }

    private val folderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        uri?.let { onDownloadFolderSelected(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        applyOrientationSetting()
        bellManager = BellManager(this)
        loadSettings()
        setupListeners()
    }

    private fun applyOrientationSetting() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val orientationSetting = prefs.getInt(KEY_ORIENTATION, 0)
        requestedOrientation = when (orientationSetting) {
            1 -> ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            else -> ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)

        // Sound enabled
        binding.switchSoundEnabled.isChecked = prefs.getBoolean(KEY_SOUND_ENABLED, true)

        // Bell sound selection
        val bellSounds = resources.getStringArray(R.array.bell_sounds)
        val bellAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, bellSounds)
        bellAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        binding.spinnerBellSound.adapter = bellAdapter
        val selectedBell = prefs.getInt(KEY_BELL_SOUND, BELL_SUN)
        binding.spinnerBellSound.setSelection(selectedBell)

        // Show initial description
        updateBellDescription(selectedBell)

        // Bell volume (0-10 representing 0-100% in 10% increments)
        val bellVolume = prefs.getInt(KEY_BELL_VOLUME, 5) // Default 50%
        binding.seekBarBellVolume.progress = bellVolume
        binding.textVolumePercent.text = "${bellVolume * 10}%"

        // Update bell sound container visibility
        updateBellSoundVisibility()

        // Vibration enabled
        binding.switchVibrationEnabled.isChecked = prefs.getBoolean(KEY_VIBRATION_ENABLED, true)

        // Orientation (Portrait or Landscape radio buttons)
        val orientation = prefs.getInt(KEY_ORIENTATION, 0)
        if (orientation == 1) {
            binding.radioLandscape.isChecked = true
        } else {
            binding.radioPortrait.isChecked = true
        }

    }

    private fun setupListeners() {
        // Sound enabled toggle
        binding.switchSoundEnabled.setOnCheckedChangeListener { _, isChecked ->
            saveSetting(KEY_SOUND_ENABLED, isChecked)
            updateBellSoundVisibility()
        }

        // Bell sound selection
        binding.spinnerBellSound.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                saveSetting(KEY_BELL_SOUND, position)
                updateBellDescription(position)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Bell volume slider
        binding.seekBarBellVolume.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: android.widget.SeekBar?, progress: Int, fromUser: Boolean) {
                binding.textVolumePercent.text = "${progress * 10}%"
                if (fromUser) {
                    saveSetting(KEY_BELL_VOLUME, progress)
                }
            }
            override fun onStartTrackingTouch(seekBar: android.widget.SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: android.widget.SeekBar?) {}
        })

        // Test sound button
        binding.btnTestSound.setOnClickListener {
            bellManager.playSound(binding.spinnerBellSound.selectedItemPosition)
            if (binding.switchVibrationEnabled.isChecked) {
                bellManager.vibrate()
            }
        }

        // Vibration enabled toggle
        binding.switchVibrationEnabled.setOnCheckedChangeListener { _, isChecked ->
            saveSetting(KEY_VIBRATION_ENABLED, isChecked)
        }

        // Orientation selection (radio buttons)
        binding.radioGroupOrientation.setOnCheckedChangeListener { _, checkedId ->
            val orientation = if (checkedId == R.id.radioLandscape) 1 else 0
            saveSetting(KEY_ORIENTATION, orientation)
            // Apply immediately
            requestedOrientation = if (orientation == 1) {
                ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            } else {
                ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
            }
        }

        // Download folder
        binding.btnDownloadFolder.setOnClickListener {
            folderPickerLauncher.launch(null)
        }

        // Export BBS list
        binding.btnExportList.setOnClickListener {
            exportLauncher.launch(getString(R.string.export_filename))
        }

        // Import BBS list
        binding.btnImportList.setOnClickListener {
            importLauncher.launch(arrayOf("application/zip", "text/xml", "application/xml"))
        }

        // Exit
        binding.btnExit.setOnClickListener {
            finish()
        }
    }

    private fun updateBellSoundVisibility() {
        val visible = if (binding.switchSoundEnabled.isChecked) View.VISIBLE else View.GONE
        binding.bellSoundContainer.visibility = visible
        binding.bellVolumeContainer.visibility = visible
        binding.btnTestSound.visibility = visible
    }

    private fun updateBellDescription(position: Int) {
        val descriptions = resources.getStringArray(R.array.bell_sound_descriptions)
        if (position in descriptions.indices) {
            binding.textBellDescription.text = descriptions[position]
        }
    }

    private fun saveSetting(key: String, value: Boolean) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putBoolean(key, value)
            .apply()
    }

    private fun saveSetting(key: String, value: Int) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putInt(key, value)
            .apply()
    }

    private fun onDownloadFolderSelected(uri: Uri) {
        contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        )

        val prefs = getSharedPreferences("file_access_settings", MODE_PRIVATE)
        prefs.edit().putString("download_dir_uri", uri.toString()).apply()

        Toast.makeText(this, R.string.transfer_folder_selected, Toast.LENGTH_SHORT).show()
    }

    private fun exportConnectionsTo(uri: Uri) {
        // Delegate to MainActivity's export logic
        setResult(Activity.RESULT_OK, Intent().apply {
            putExtra("action", "export")
            putExtra("uri", uri.toString())
        })
        finish()  // Return to MainActivity to perform the export
    }

    private fun importConnectionsFrom(uri: Uri) {
        // Delegate to MainActivity's import logic
        setResult(Activity.RESULT_OK, Intent().apply {
            putExtra("action", "import")
            putExtra("uri", uri.toString())
        })
        finish()  // Return to MainActivity to perform the import
    }

    override fun onDestroy() {
        super.onDestroy()
        bellManager.release()
    }
}
