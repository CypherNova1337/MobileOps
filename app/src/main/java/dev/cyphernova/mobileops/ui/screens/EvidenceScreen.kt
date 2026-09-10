package dev.cyphernova.mobileops.ui.screens

import android.content.Intent
import androidx.core.content.FileProvider
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.ui.MobileOpsViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun EvidenceScreen(viewModel: MobileOpsViewModel) {
    val findings by viewModel.findings.collectAsState()
    val context = LocalContext.current

    LazyColumn(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        val share = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, viewModel.renderReport())
                            putExtra(Intent.EXTRA_SUBJECT, "MobileOps report")
                        }
                        context.startActivity(Intent.createChooser(share, "Export report"))
                    },
                    enabled = findings.isNotEmpty(),
                ) { Text("Export report") }

                OutlinedButton(onClick = viewModel::clearEvidence) { Text("Clear log") }

                // Only appears once interception has generated a CA to install.
                viewModel.caCertificateFile()?.let { certificate ->
                    OutlinedButton(
                        onClick = {
                            val uri = FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.files",
                                certificate,
                            )
                            val share = Intent(Intent.ACTION_SEND).apply {
                                type = "application/x-pem-file"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            context.startActivity(Intent.createChooser(share, "Export CA certificate"))
                        },
                    ) { Text("Export CA") }
                }
            }
        }

        if (findings.isEmpty()) {
            item {
                Text(
                    "No findings recorded yet. Run a module and everything it observes lands here.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        items(findings.asReversed()) { finding -> FindingCard(finding) }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    finding.severity.label.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = severityColour(finding.severity),
                )
                Text(
                    TIME.format(Date(finding.observedAtEpochMs)),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(finding.title, fontWeight = FontWeight.SemiBold)
            Text(
                finding.subject,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                finding.detail,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

private fun severityColour(severity: Severity): Color = when (severity) {
    Severity.CRITICAL -> Color(0xFFDC2626)
    Severity.HIGH -> Color(0xFFEA580C)
    Severity.MEDIUM -> Color(0xFFCA8A04)
    Severity.LOW -> Color(0xFF0891B2)
    Severity.INFO -> Color(0xFF64748B)
}

private val TIME = SimpleDateFormat("HH:mm:ss", Locale.US)
