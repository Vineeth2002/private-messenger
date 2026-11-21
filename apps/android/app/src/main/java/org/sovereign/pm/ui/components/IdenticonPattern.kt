package org.sovereign.pm.ui.components

/** Decorative avatar pattern only. It is not a security identifier or fingerprint. */
object IdenticonPattern {
    fun generateMatrix(seed: String): List<List<Boolean>> {
        val hash = seed.fold(0x811c9dc5.toInt()) { acc, ch -> (acc xor ch.code) * 0x01000193 }
        val halfGrid = BooleanArray(15) { idx -> ((hash ushr (idx % 24)) and 1) == 1 }
        return List(5) { row ->
            List(5) { col -> halfGrid[row * 3 + if (col < 3) col else 4 - col] }
        }
    }
}
