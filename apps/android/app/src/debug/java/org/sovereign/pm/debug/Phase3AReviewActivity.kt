package org.sovereign.pm.debug

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.sovereign.pm.app.Phase3APreviewHost

/** Debug-only preview Activity. It does not initialize or access production identity state. */
class Phase3AReviewActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { Phase3APreviewHost(onCloseReviewActivity = { finish() }) }
    }
}
