package com.loandesk.app

import android.annotation.SuppressLint
import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.ProgressBar
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var webView: WebView
    private lateinit var progress: ProgressBar
    private lateinit var status: TextView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.rgb(16, 30, 58)
        window.navigationBarColor = Color.rgb(16, 30, 58)
        window.decorView.systemUiVisibility = 0

        val root = FrameLayout(this).apply { setBackgroundColor(Color.rgb(244, 247, 251)) }
        webView = WebView(this).apply {
            setBackgroundColor(Color.rgb(244, 247, 251))
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
            webChromeClient = WebChromeClient()
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val uri = request?.url ?: return true
                    val base = android.net.Uri.parse(BuildConfig.APP_URL)
                    return uri.scheme != base.scheme || uri.host != base.host
                }
                override fun onPageFinished(view: WebView?, url: String?) {
                    progress.visibility = View.GONE
                    status.visibility = View.GONE
                    webView.visibility = View.VISIBLE
                }
                override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: android.webkit.WebResourceError?) {
                    if (request?.isForMainFrame == true) {
                        progress.visibility = View.GONE
                        status.visibility = View.VISIBLE
                        status.text = "LoanDesk could not connect. Check the server address and your internet connection, then reopen the app."
                    }
                }
            }
        }
        root.addView(webView, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))

        progress = ProgressBar(this).apply { isIndeterminate = true }
        val progressParams = FrameLayout.LayoutParams(72, 72, Gravity.CENTER)
        root.addView(progress, progressParams)

        status = TextView(this).apply {
            text = "Opening LoanDesk…"
            textSize = 15f
            setTextColor(Color.rgb(16, 30, 58))
            gravity = Gravity.CENTER
            setPadding(32, 32, 32, 32)
            visibility = View.GONE
        }
        root.addView(status, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.CENTER))
        setContentView(root)
        webView.loadUrl(BuildConfig.APP_URL)
    }

    @Deprecated("Deprecated in Android API, kept for older Android back navigation")
    override fun onBackPressed() {
        if (::webView.isInitialized && webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }

    override fun onDestroy() {
        if (::webView.isInitialized) {
            webView.stopLoading()
            webView.destroy()
        }
        super.onDestroy()
    }
}
