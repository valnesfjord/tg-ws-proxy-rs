package com.github.valnesfjord.tg_ws_proxy_rs.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.vectorResource
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.github.valnesfjord.tg_ws_proxy_rs.ProxyViewModel
import com.github.valnesfjord.tg_ws_proxy_rs.R

@Composable
fun TgWsTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = if (dark) darkColorScheme() else lightColorScheme(),
        content = content,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProxyScreen(viewModel: ProxyViewModel) {
    val args by viewModel.args.collectAsStateWithLifecycle()
    val running by viewModel.running.collectAsStateWithLifecycle()
    val logs by viewModel.logs.collectAsStateWithLifecycle()
    val tgLink by viewModel.tgLink.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.scrollToItem(logs.lastIndex)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    IconButton(onClick = viewModel::openRepo) {
                        Icon(
                            imageVector = ImageVector.vectorResource(R.drawable.ic_github),
                            contentDescription = stringResource(R.string.view_on_github),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            OutlinedTextField(
                value = args,
                onValueChange = viewModel::updateArgs,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.args_label)) },
                minLines = 3,
                maxLines = 8,
                enabled = !running,
            )

            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = { if (running) viewModel.stop() else viewModel.start() },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(stringResource(if (running) R.string.stop else R.string.start))
                }
                StatusDot(running)
                Text(
                    stringResource(if (running) R.string.status_running else R.string.status_stopped),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            if (tgLink != null) {
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = viewModel::openLink,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.open_telegram_link))
                }
            }

            if (error != null) {
                Spacer(Modifier.height(8.dp))
                Text(
                    error.orEmpty(),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.log_label),
                style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(4.dp))

            SelectionContainer(modifier = Modifier.fillMaxSize()) {
                LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                    itemsIndexed(logs, key = { index, line -> "$index:$line" }) { _, line ->
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 1.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusDot(running: Boolean) {
    val color = if (running) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.outline
    }
    Surface(
        modifier = Modifier.size(12.dp),
        shape = CircleShape,
        color = color,
    ) {}
}
