package org.example
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.jsoup.Jsoup
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Security
import java.security.spec.X509EncodedKeySpec

class new(var username: String,var password: String) {
    class RedirectCookieJar : CookieJar {
        private val cookieStore: MutableMap<String, MutableList<Cookie>> = mutableMapOf()

        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
            println(url.host + cookies)
            if (cookieStore[url.host] == null) {
                cookieStore[url.host] = mutableListOf()
            }
            cookieStore[url.host]?.let { cookieStores->
                cookieStores.replaceAll { item ->
                    val newItem = cookies.find { it.name == item.name }
                    newItem?:item
                }
                cookies.forEach { item ->
                    if (!cookieStores.any { it.name == item.name }) {
                        cookieStores.add(item)
                    }
                }
            }
//            val commonKeys = cookieStore[url.host]?.map { it.name }?.intersect(cookies.map { it.name })
//            commonKeys?.let{
//                println("两个列表中有相同的 key：$commonKeys")
//            }
            // 遍历第二个列表，如果第一个列表中没有相同 key 的对象，则添加到第一个列表中

//            cookieStore[url.host]?.addAll(cookies)
            println("cookieStore:"+cookieStore)
        }

        override fun loadForRequest(url: HttpUrl): List<Cookie> {
            return cookieStore[url.host] ?: mutableListOf()
        }
        fun getCookies(): Map<String, List<Cookie>> {
            return cookieStore
        }
    }
    var logincookies = ""
    // 创建 OkHttpClient 实例
    val client = OkHttpClient.Builder()
        .followRedirects(false) // 禁用 OkHttp 自动重定向处理
        .followSslRedirects(false)
        .cookieJar(RedirectCookieJar())
        .build()
    var ltValue = ""
    var publicKey = ""
    // Encrypt credentials
    var encryptedUsername = ""
    var encryptedPassword = ""
    fun getLtValue() {
        val request = Request.Builder()
            .url("https://zhlgd.whut.edu.cn/tpass/login?service=https%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2F")
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            var tempCookies = response.headers("Set-Cookie")
            println(tempCookies)
            tempCookies.forEach {
                if(it.contains("JSESSIONID")){
                    logincookies += it.substring(it.indexOf("JSESSIONID"),it.indexOf(";"))+";"
                    println(logincookies)
                }
            }
            val document = Jsoup.parse(response.body?.string())
            ltValue = document.select("input[name=lt]").attr("value")
            println(ltValue)
        }

    }

    data class PublicKeyResponse(
        @SerializedName("publicKey") val publicKey: String
    )

    fun getPublicKey() {
        val mediaType = "text/plain".toMediaType()
        val body = "".toRequestBody(mediaType)
        val request = Request.Builder()
            .url("https://zhlgd.whut.edu.cn/tpass/rsa?skipWechat=true")
            .post(body)
            .build()
        client.newCall(request).execute().use { response ->
            var tempCookies = response.headers("Set-Cookie")
            println(tempCookies)
            tempCookies.forEach {
                if(it.contains("JSESSIONID")){
                    logincookies += it.substring(it.indexOf("JSESSIONID"),it.indexOf(";"))+";"
                    println(logincookies)
                }
            }
            val jsonResponse = response.body?.string()
            println(jsonResponse)
            val publicKeyResponse = Gson().fromJson(jsonResponse, PublicKeyResponse::class.java)
            publicKey = publicKeyResponse.publicKey
            println(publicKey)
        }

    }
    fun rsaEncode(){
        // Encrypt credentials
        encryptedUsername = rsaEncrypt(username, publicKey)
        encryptedPassword = rsaEncrypt(password, publicKey)
        println("Encrypted Username: $encryptedUsername")
        println("Encrypted Password: $encryptedPassword")
    }
    fun rsaEncrypt(data: String, publicKey: String): String {
        Security.addProvider(BouncyCastleProvider())
        val keySpec = X509EncodedKeySpec(Base64.decode(publicKey))
        val keyFactory = KeyFactory.getInstance("RSA")
        val rsaPublicKey = keyFactory.generatePublic(keySpec)

        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, rsaPublicKey)
        val encryptedData = cipher.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return Base64.toBase64String(encryptedData)
    }
    // 模拟登录请求
    fun login() {
        // Define headers
        val headers = Headers.Builder()
            .add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .add("Accept-Encoding", "gzip, deflate, br")
            .add("Accept-Language", "zh-CN,zh;q=0.9")
            .add("Cache-Control", "max-age=0")
            .add("Connection", "keep-alive")
            .add("Content-Type", "application/x-www-form-urlencoded")
            .add("Host", "zhlgd.whut.edu.cn")
            .add("Origin", "https://zhlgd.whut.edu.cn")
            .add("Referer", "https://zhlgd.whut.edu.cn/tpass/login?service=https%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2F")
            .add("Sec-Ch-Ua", "\"Not=A?Brand\";v=\"99\", \"Chromium\";v=\"118\"")
            .add("Sec-Ch-Ua-Mobile", "?0")
            .add("Sec-Ch-Ua-Platform", "\"Windows\"")
            .add("Sec-Fetch-Dest", "document")
            .add("Sec-Fetch-Mode", "navigate")
            .add("Sec-Fetch-Site", "same-origin")
            .add("Sec-Fetch-User", "?1")
            .add("Upgrade-Insecure-Requests", "1")
            .add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36")
            .build()
        val loginUrl = "https://zhlgd.whut.edu.cn/tpass/login?service=https%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2F"
        val formBody = FormBody.Builder()
            .add("rsa","")
            .add("ul", encryptedUsername)
            .add("pl", encryptedPassword)
            .add("lt", ltValue)
            .add("execution", "e1s1")
            .add("_eventId", "submit")
            .build()

        var request = Request.Builder()
            .url(loginUrl)
            .headers(headers)
            .post(formBody)
            .build()

        var response: Response = client.newCall(request).execute()
        println(response.body?.string())
        var tempCookies = response.headers("Set-Cookie")
        println(tempCookies)
        tempCookies.forEach {
            if(it.contains("JSESSIONID")){
                logincookies += it.substring(it.indexOf("JSESSIONID"),it.indexOf(";"))+";"
                println(logincookies)
            }
        }
        while (response.isRedirect) {
            val location = response.header("Location") ?: throw IOException("No Location header in response")
            var tempCookies = response.headers("Set-Cookie")
            println("cookies"+tempCookies)
            tempCookies.forEach {
                if(it.contains("CASTGC")){
                    logincookies += it.substring(it.indexOf("CASTGC"),it.indexOf(";"))+";"
                    println(logincookies)
                }
            }

            request = Request.Builder()
                .url(location)
                .get()
                .build()
            response = client.newCall(request).execute()
            response.body?.let {
                println(it.string())
            }


        }
        val cookieJar = client.cookieJar as RedirectCookieJar
        var cookies = cookieJar.getCookies()
        println("Cookies: $cookies")
        println(cookies["zhlgd.whut.edu.cn"])
        cookies["zhlgd.whut.edu.cn"]?.forEach {
            if(it.name.contains("route")){
                logincookies += it.name+"="+it.value+";"
            }
            if(it.name.contains("tp_up")){
                logincookies += it.name+"="+it.value+";"
            }
        }
        println(logincookies)

//        val client1 = OkHttpClient.Builder()
//            .followRedirects(true) // 禁用 OkHttp 自动重定向处理
//            .followSslRedirects(true)
//            .cookieJar(RedirectCookieJar())
//            .build()

        request = Request.Builder()
            .url("http://zhlgd.whut.edu.cn/tpass/login?service=http%3A%2F%2Fcwsf.whut.edu.cn%2FcasLogin")
            .addHeader("Cookie", logincookies)
            .get()
            .build()
        response = client.newCall(request).execute()
        var tempCookies1 = response.headers("Set-Cookie")
        println(tempCookies1)
        println("Login Response: ${response.body?.string()}")
        while (response.isRedirect) {
            val location = response.header("Location") ?: throw IOException("No Location header in response")
            var tempCookies = response.headers("Set-Cookie")
            println(tempCookies)
            println("location:"+location)
            request = Request.Builder()
                .url(location)
                .addHeader("Cookie", logincookies)
                .get()
                .build()
            response = client.newCall(request).execute()

        }
//        println(response.body?.string())
        val cookieJar1 = client.cookieJar as RedirectCookieJar
        var cookies1 = cookieJar1.getCookies()
        var dianfeicookies = ""
        println(cookies1)
        cookies1["cwsf.whut.edu.cn"]?.forEach {
            if(it.name.contains("JSESSIONID")){
                dianfeicookies += it.name+"="+it.value+";"
                println(dianfeicookies)
            }
        }
        val client = OkHttpClient()
        request = Request.Builder()
            .url("http://cwsf.whut.edu.cn/queryReserve?meterId=0311.004093.1&factorycode=E035")
            .addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .addHeader("Accept-Encoding", "gzip, deflate")
            .addHeader("Accept-Language", "zh-CN,zh;q=0.9,en-GB;q=0.8,en-US;q=0.7,en;q=0.6")
            .addHeader("Cache-Control", "no-cache")
            .addHeader("Connection", "keep-alive")
            .addHeader("Cookie", dianfeicookies)
            .addHeader("Host", "cwsf.whut.edu.cn")
            .addHeader("Pragma", "no-cache")
            .addHeader("Upgrade-Insecure-Requests", "1")
            .addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.76")
            .build()
        response = client.newCall(request).execute()
        println("Login Response: ${response.body?.string()}")


//        request = Request.Builder()
//            .url("http://zhlgd.whut.edu.cn/tpass/login?service=http%3A%2F%2Fcwsf.whut.edu.cn%2FcasLogin")
//            .addHeader("Cookie",logincookies)
//            .get()
//            .build()
//        response = client.newCall(request).execute()
//        println("Login Response: ${response.body?.string()}")
//        while (response.isRedirect) {
//            val location = response.header("Location") ?: throw IOException("No Location header in response")
//            println("location:"+location)
//            request = Request.Builder()
//                .url(location)
//                .get()
//                .build()
//            response = client.newCall(request).execute()
//        }
//        println("Login Response: ${response.body?.string()}")
//        if (!response.isSuccessful) {
//            throw IOException("Unexpected code $response")
//        }

    }
    fun getdianfei(){
        val loginUrl = "http://cwsf.whut.edu.cn/casLogin"


        val loginRequest = Request.Builder()
            .url(loginUrl)
            .get()
            .build()

        client.newCall(loginRequest).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Unexpected code $response")
            println("Login Response: ${response.body?.string()}")
        }
    }
    fun getdianfei1(){
        val loginUrl = "http://zhlgd.whut.edu.cn/tpass/login?service=http%3A%2F%2Fcwsf.whut.edu.cn%2FcasLogin"


        val loginRequest = Request.Builder()
            .url(loginUrl)
            .get()
            .build()

        client.newCall(loginRequest).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Unexpected code $response")
            println("Login Response: ${response.body?.string()}")
            println(response.header("Location"))
        }
    }
    fun getdianfei2(){
        val loginUrl = "https://zhlgd.whut.edu.cn/tpass/login?service=http%3A%2F%2Fcwsf.whut.edu.cn%2FcasLogin"


        val loginRequest = Request.Builder()
            .url(loginUrl)
            .get()
            .build()

        client.newCall(loginRequest).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Unexpected code $response")
            println("Login Response: ${response.body?.string()}")
            println(response.header("Location"))
        }
    }
    fun getdianfei3(){
        val loginUrl = "https://zhlgd.whut.edu.cn/tpass/login?service=http%3A%2F%2Fcwsf.whut.edu.cn%2FcasLogin"


        val loginRequest = Request.Builder()
            .url(loginUrl)
            .get()
            .build()

        client.newCall(loginRequest).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Unexpected code $response")
            println("Login Response: ${response.body?.string()}")
            println(response.header("Location"))
        }
    }
}



//// 模拟登录请求
//fun login2(username: String, password: String): String? {
//    val loginUrl = "https://zhlgd.whut.edu.cn/tp_up/"
//    val formBody = FormBody.Builder()
////        .add("username", username)
////        .add("password", password)
//        .build()
//
//    val loginRequest = Request.Builder()
//        .url(loginUrl)
//        .post(formBody)
//        .build()
//
//    client.newCall(loginRequest).execute().use { response ->
//        if (!response.isSuccessful) throw IOException("Unexpected code $response")
//        println(response.header("Set-Cookie"))
//        return response.header("Set-Cookie") // 获取登录后的 Cookie
//    }
//}

// 使用获取的 Cookie 进行跨站点请求
//fun makeAuthenticatedRequest(cookie: String?) {
//    val targetUrl = "https://zhlgd.whut.edu.cn/tpass/rsa?skipWechat=true"
//
//    val request = Request.Builder()
//        .url(targetUrl)
//        .addHeader("Cookie", cookie ?: "")
//        .build()
//
//    client.newCall(request).execute().use { response ->
////        if (!response.isSuccessful) throw IOException("Unexpected code $response")
//        println(response.header("Set-Cookie"))
//    }
//}


fun main(){
    // 示例调用
    var new = new("","")
    new.getLtValue()
    new.getPublicKey()
    new.rsaEncode()
    new.login()
//    new.getdianfei()
//    new.getdianfei1()
//    new.getdianfei2()
}