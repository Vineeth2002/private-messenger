package org.sovereign.pm.messaging

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth

@Composable
internal fun EmailAuthOnboardingScreen(
    context: Context,
    simPrefs: SharedPreferences,
    onCompleted: () -> Unit,
) {
    var isSignUp by remember { mutableStateOf(true) }
    var displayName by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var errorText by remember { mutableStateOf<String?>(null) }

    fun saveAccountAndEnter(cleanEmail: String, cleanName: String) {
        simPrefs.edit()
            .putString("registered_phone", cleanEmail)
            .putString("user_display_name", cleanName.ifBlank { cleanEmail.substringBefore("@") })
            .putInt("bound_sim_sub_id", -1)
            .putString("bound_sim_carrier", "Email Account")
            .putBoolean("sim_binding_test_bypass", true)
            .apply()
        onCompleted()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "Sovereign PM",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = if (isSignUp) "Create your private messaging account" else "Sign in to your account",
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(28.dp))

        if (isSignUp) {
            OutlinedTextField(
                value = displayName,
                onValueChange = { displayName = it },
                label = { Text("Your Name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
            )
            Spacer(modifier = Modifier.height(12.dp))
        }

        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Email Address") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
        )
        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password (min 6 characters)") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
        )

        if (!errorText.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = errorText!!,
                color = MaterialTheme.colorScheme.error,
                fontSize = 13.sp,
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        Button(
            enabled = !isLoading,
            onClick = {
                val cleanEmail = email.trim()
                val cleanName = displayName.trim()
                if (!cleanEmail.contains("@") || !cleanEmail.contains(".")) {
                    errorText = "Enter a valid email address."
                    return@Button
                }
                if (password.length < 6) {
                    errorText = "Password must be at least 6 characters."
                    return@Button
                }
                if (FirebaseApp.getApps(context).isEmpty()) {
                    errorText = "Firebase is not configured on this build."
                    return@Button
                }
                isLoading = true
                errorText = null
                val auth = FirebaseAuth.getInstance()
                val task = if (isSignUp) {
                    auth.createUserWithEmailAndPassword(cleanEmail, password)
                } else {
                    auth.signInWithEmailAndPassword(cleanEmail, password)
                }
                task.addOnSuccessListener {
                    if (isSignUp) {
                        auth.currentUser?.sendEmailVerification()
                    }
                    isLoading = false
                    saveAccountAndEnter(cleanEmail, cleanName)
                }.addOnFailureListener { e ->
                    isLoading = false
                    errorText = e.localizedMessage ?: "Authentication failed. Please try again."
                }
            },
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
        ) {
            Text(
                text = when {
                    isLoading -> "Please wait..."
                    isSignUp -> "Create Account"
                    else -> "Sign In"
                },
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (isSignUp) "Already have an account?" else "New to Sovereign PM?",
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onClick = {
                isSignUp = !isSignUp
                errorText = null
            }) {
                Text(if (isSignUp) "Sign In" else "Create Account")
            }
        }
    }
}
