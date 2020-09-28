package com.thegrizzlylabs.sardineandroid.impl;

import android.text.TextUtils;
import android.net.TrafficStats;
import android.os.StrictMode;
import android.util.Log;

import com.thegrizzlylabs.sardineandroid.DavAce;
import com.thegrizzlylabs.sardineandroid.DavAcl;
import com.thegrizzlylabs.sardineandroid.DavPrincipal;
import com.thegrizzlylabs.sardineandroid.DavQuota;
import com.thegrizzlylabs.sardineandroid.DavResource;
import com.thegrizzlylabs.sardineandroid.Sardine;
import com.thegrizzlylabs.sardineandroid.impl.handler.ExistsResponseHandler;
import com.thegrizzlylabs.sardineandroid.impl.handler.InputStreamResponseHandler;
import com.thegrizzlylabs.sardineandroid.impl.handler.LockResponseHandler;
import com.thegrizzlylabs.sardineandroid.impl.handler.MultiStatusResponseHandler;
import com.thegrizzlylabs.sardineandroid.impl.handler.ResourcesResponseHandler;
import com.thegrizzlylabs.sardineandroid.impl.handler.ResponseHandler;
import com.thegrizzlylabs.sardineandroid.impl.handler.VoidResponseHandler;
import com.thegrizzlylabs.sardineandroid.model.Ace;
import com.thegrizzlylabs.sardineandroid.model.Acl;
import com.thegrizzlylabs.sardineandroid.model.Allprop;
import com.thegrizzlylabs.sardineandroid.model.Exclusive;
import com.thegrizzlylabs.sardineandroid.model.Group;
import com.thegrizzlylabs.sardineandroid.model.Lockinfo;
import com.thegrizzlylabs.sardineandroid.model.Lockscope;
import com.thegrizzlylabs.sardineandroid.model.Locktype;
import com.thegrizzlylabs.sardineandroid.model.Multistatus;
import com.thegrizzlylabs.sardineandroid.model.Owner;
import com.thegrizzlylabs.sardineandroid.model.PrincipalCollectionSet;
import com.thegrizzlylabs.sardineandroid.model.Prop;
import com.thegrizzlylabs.sardineandroid.model.Propertyupdate;
import com.thegrizzlylabs.sardineandroid.model.Propfind;
import com.thegrizzlylabs.sardineandroid.model.Propname;
import com.thegrizzlylabs.sardineandroid.model.Propstat;
import com.thegrizzlylabs.sardineandroid.model.QuotaAvailableBytes;
import com.thegrizzlylabs.sardineandroid.model.QuotaUsedBytes;
import com.thegrizzlylabs.sardineandroid.model.Remove;
import com.thegrizzlylabs.sardineandroid.model.SearchRequest;
import com.thegrizzlylabs.sardineandroid.model.Set;
import com.thegrizzlylabs.sardineandroid.model.Write;
import com.thegrizzlylabs.sardineandroid.report.SardineReport;
import com.thegrizzlylabs.sardineandroid.util.SardineUtil;

import org.w3c.dom.Element;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.net.SocketFactory;
import javax.xml.namespace.QName;

import okhttp3.Credentials;
import okhttp3.Headers;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;
import okio.BufferedSink;
import okio.Okio;

/**
 * Created by guillaume on 08/11/2017.
 */

public class OkHttpSardine implements Sardine {

    private OkHttpClient client;
    private String TAG = "OkHttpSardine";
    private int THREAD_STATS_TAG = 20190228;

    public OkHttpSardine() {
        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(HttpLoggingInterceptor.Level.HEADERS);
        this.client = new OkHttpClient.Builder()
                // Work-around for HTTP/2 bug in OkHttp where it goes into infinite retries, see
                // https://github.com/square/okhttp/issues/3312.
                .protocols(Arrays.asList(Protocol.HTTP_1_1))
                // Work-around for StrictMode OkHttp incompatibility, see
                // https://github.com/square/okhttp/issues/3537.
                .socketFactory(
                        new DelegatingSocketFactory(SocketFactory.getDefault()) {
                                @Override protected Socket configureSocket(Socket socket) throws IOException {
                                        // This is hacky as we'll set this on every socket creation
                                        // instead of once per thread, but there seems to be no way to
                                        // do this cleanly :-(
                                        TrafficStats.setThreadStatsTag(THREAD_STATS_TAG);
                                        TrafficStats.tagSocket(socket);
                                        // Make sure we detect everything and log it.
                                        StrictMode.setThreadPolicy(
                                                new StrictMode.ThreadPolicy.Builder()
                                                        .detectAll()
                                                        .permitDiskReads()
                                                        .permitDiskWrites()
                                                        .permitNetwork()
                                                        .penaltyLog()
                                                        .build());
                                        StrictMode.setVmPolicy(
                                                new StrictMode.VmPolicy.Builder()
                                                        .detectAll()
                                                        .penaltyLog()
                                                        .build());
                                        return socket;
                                }
                        })
                .addInterceptor(logging)
                .build();
    }

    public OkHttpSardine(OkHttpClient client) {
        this.client = client;
    }

    @Override
    public void setCredentials(String username, String password, boolean isPreemptive) {
        OkHttpClient.Builder builder = client.newBuilder();
        if (isPreemptive) {
            builder.addInterceptor(new AuthenticationInterceptor(username, password));
        } else {
            builder.authenticator(new BasicAuthenticator(username, password));
        }
        this.client = builder.build();
    }

    @Override
    public void setCredentials(String username, String password) {
        setCredentials(username, password, false);
    }

    private class AuthenticationInterceptor implements Interceptor {

        private String userName;
        private String password;

        public AuthenticationInterceptor(String userName, String password) {
            this.userName = userName;
            this.password = password;
        }

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request().newBuilder().addHeader("Authorization", Credentials.basic(userName, password, SardineUtil.standardUTF8())).build();
            return chain.proceed(request);
        }
    }

    @Override
    public List<DavResource> getResources(String url) throws IOException {
        return list(url);
    }

    @Override
    public List<DavResource> list(String url) throws IOException {
        return list(url, 1);
    }

    @Override
    public List<DavResource> list(String url, int depth) throws IOException {
        return list(url, depth, true, false);
    }

    @Override
    public List<DavResource> list(String url, int depth, java.util.Set<QName> props) throws IOException {
        Propfind body = new Propfind();
        Prop prop = new Prop();
//        prop.setGetcontentlength(objectFactory.createGetcontentlength());
//        prop.setGetlastmodified(objectFactory.createGetlastmodified());
//        prop.setCreationdate(objectFactory.createCreationdate());
//        prop.setDisplayname(objectFactory.createDisplayname());
//        prop.setGetcontenttype(objectFactory.createGetcontenttype());
//        prop.setResourcetype(objectFactory.createResourcetype());
//        prop.setGetetag(objectFactory.createGetetag());
        addCustomProperties(prop, props);
        body.setProp(prop);
        return propfind(url, depth, body);
    }

    @Override
    public List<DavResource> list(String url, int depth, boolean allProp, boolean propName) throws IOException {
        if (!allProp && !propName) {
            return list(url, depth, Collections.<QName>emptySet());
        }
        Propfind body = new Propfind();
        if (allProp) {
            body.setAllprop(new Allprop());
        }
        if (propName) {
            body.setPropname(new Propname());
        }
        return propfind(url, depth, body);
    }

    @Override
    public List<DavResource> propfind(String url, int depth, java.util.Set<QName> props) throws IOException {
        Propfind body = new Propfind();
        Prop prop = new Prop();
        addCustomProperties(prop, props);
        body.setProp(prop);
        return propfind(url, depth, body);
    }

    private void addCustomProperties(Prop prop, java.util.Set<QName> props) {
        List<Element> any = prop.getAny();
        for (QName entry : props) {
            Element element = SardineUtil.createElement(entry);
            any.add(element);
        }
    }

    protected List<DavResource> propfind(String url, int depth, Propfind body) throws IOException {
        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", depth < 0 ? "infinity" : Integer.toString(depth))
                .method("PROPFIND", requestBody)
                .build();

        return execute(request, new ResourcesResponseHandler());
    }

    @Override
    public <T> T report(String url, int depth, SardineReport<T> report) throws IOException {
        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), report.toXml());
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", depth < 0 ? "infinity" : Integer.toString(depth))
                .method("REPORT", requestBody)
                .build();

        Multistatus multistatus = this.execute(request, new MultiStatusResponseHandler());
        return report.fromMultistatus(multistatus);
    }

    @Override
    public List<DavResource> search(String url, String language, String query) throws IOException {
        SearchRequest searchBody = new SearchRequest(language, query);
        String body = SardineUtil.toXml(searchBody);
        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .method("SEARCH", requestBody)
                .build();

        return execute(request, new ResourcesResponseHandler());
    }

    @Override
    public void setCustomProps(String url, Map<String, String> set, List<String> remove) throws IOException {
        this.patch(url, SardineUtil.toQName(set), SardineUtil.toQName(remove));
    }

    @Override
    public List<DavResource> patch(String url, Map<QName, String> setProps) throws IOException {
        return this.patch(url, setProps, Collections.<QName>emptyList());
    }

    @Override
    public List<DavResource> patch(String url, Map<QName, String> setProps, List<QName> removeProps) throws IOException {
        List<Element> setPropsElements = new ArrayList<>();
        for (Map.Entry<QName, String> entry : setProps.entrySet()) {
            Element element = SardineUtil.createElement(entry.getKey());
            element.setTextContent(entry.getValue());
            setPropsElements.add(element);
        }
        return this.patch(url, setPropsElements, removeProps);
    }

    @Override
    public List<DavResource> patch(String url, List<Element> setProps, List<QName> removeProps) throws IOException {
        // Build WebDAV <code>PROPPATCH</code> entity.
        Propertyupdate body = new Propertyupdate();
        // Add properties
        {
            Set set = new Set();
            body.getRemoveOrSet().add(set);
            Prop prop = new Prop();
            // Returns a reference to the live list
            List<Element> any = prop.getAny();
            any.addAll(setProps);
            set.setProp(prop);
        }
        // Remove properties
        {
            Remove remove = new Remove();
            body.getRemoveOrSet().add(remove);
            Prop prop = new Prop();
            // Returns a reference to the live list
            List<Element> any = prop.getAny();
            for (QName entry : removeProps) {
                Element element = SardineUtil.createElement(entry);
                any.add(element);
            }
            remove.setProp(prop);
        }

        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .method("PROPPATCH", requestBody)
                .build();

        return execute(request, new ResourcesResponseHandler());
    }

    @Override
    public InputStream get(String url) throws IOException {
        return this.get(url, Collections.<String, String>emptyMap());
    }

    @Override
    public InputStream get(String url, Map<String, String> headers) throws IOException {
        return this.get(url, Headers.of(headers));
    }

    public InputStream get(String url, Headers headers) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .get()
                .headers(headers)
                .build();

        return execute(request, new InputStreamResponseHandler());
    }

    @Override
    public void put(String url, byte[] data) throws IOException {
        this.put(url, data, null);
    }

    @Override
    public void put(String url, byte[] data, String contentType) throws IOException {
        MediaType mediaType = contentType == null ? null : MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(mediaType, data);
        put(url, requestBody);
    }

    @Override
    public void put(String url, File localFile, String contentType) throws IOException {
        //don't use ExpectContinue for repetable FileEntity, some web server (IIS for exmaple) may return 400 bad request after retry
        put(url, localFile, contentType, false);
    }

    @Override
    public void put(String url, File localFile, String contentType, boolean expectContinue) throws IOException {
        put(url, localFile, contentType, expectContinue, null);
    }

    @Override
    public void put(String url, File localFile, String contentType, boolean expectContinue, String lockToken) throws IOException {
        MediaType mediaType = contentType == null ? null : MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(mediaType, localFile);
        Headers.Builder headersBuilder = new Headers.Builder();
        if (expectContinue) {
            headersBuilder.add("Expect", "100-Continue");
        }
        if (!TextUtils.isEmpty(lockToken)) {
            addLockTokenToHeaders(headersBuilder, url, lockToken);
        }
        put(url, requestBody, headersBuilder.build());
    }
    @Override
    public void put(String url, InputStream dataStream) throws IOException {
        InputStreamRequestBody requestBody = new InputStreamRequestBody(
                null, -1, dataStream);
        Headers.Builder headersBuilder = new Headers.Builder();
        headersBuilder.add("Transfer-encoding", "chunked");
        put(url, requestBody, headersBuilder.build());

    }

    @Override
    public void put(String url, InputStream dataStream, String contentType) throws IOException {
        MediaType mediaType = contentType == null ? null : MediaType.parse(contentType);
        InputStreamRequestBody requestBody = new InputStreamRequestBody(
                mediaType, -1, dataStream);
        Headers.Builder headersBuilder = new Headers.Builder();
        headersBuilder.add("Transfer-encoding", "chunked");
        put(url, requestBody, headersBuilder.build());
    }

    @Override
    public void put(String url, InputStream dataStream, String contentType, boolean expectContinue) throws IOException {
        MediaType mediaType = contentType == null ? null : MediaType.parse(contentType);
        InputStreamRequestBody requestBody = new InputStreamRequestBody(
                mediaType, -1, dataStream);
        Headers.Builder headersBuilder = new Headers.Builder();
        headersBuilder.add("Transfer-encoding", "chunked");
        if (expectContinue) {
            headersBuilder.add("Expect", "100-Continue");
        }
        put(url, requestBody, headersBuilder.build());
    }
    @Override
    public void put(String url, InputStream dataStream, String contentType, boolean expectContinue, long contentLength) throws IOException {
        MediaType mediaType = contentType == null ? null : MediaType.parse(contentType);
        InputStreamRequestBody requestBody = new InputStreamRequestBody(
                mediaType, contentLength, dataStream);
        Headers.Builder headersBuilder = new Headers.Builder();
        if (contentLength == -1) {
            headersBuilder.add("Transfer-encoding", "chunked");
        }
        if (expectContinue) {
            headersBuilder.add("Expect", "100-Continue");
        }
        put(url, requestBody, headersBuilder.build());
    }

    public void put(String url, InputStream dataStream, Map<String, String> headers) throws IOException {
        InputStreamRequestBody requestBody = new InputStreamRequestBody(
                null, -1, dataStream);
        Headers.Builder headersBuilder = new Headers.Builder();
        headersBuilder.add("Transfer-encoding", "chunked");
        headersBuilder.addAll(Headers.of(headers));
        put(url, requestBody, headersBuilder.build());
    }

    private class InputStreamRequestBody extends RequestBody {
        private MediaType contentType;
        private long contentLength;
        private InputStream stream;

        public InputStreamRequestBody(MediaType contentType, long contentLength, InputStream stream) {
            this.contentType = contentType;
            this.contentLength = contentLength;
            this.stream = stream;
        }

        @Override
        public MediaType contentType() {
            return contentType;
        }

        @Override
        public long contentLength() throws IOException { return contentLength; }

        @Override
        public void writeTo(BufferedSink sink) throws IOException {
            if (this.stream == null) {
                throw new IOException("Stream is null, possibly exhausted and abandoned already?");
            }
            try {
                long readBytes = sink.writeAll(Okio.source(stream));
                Log.i(TAG, String.format("InputStreamRequestBody.writeTo wrote %d bytes.", readBytes));
            } catch (Exception ex) {
                Log.i(TAG, "Got exception, trying to reset the stream.", ex);
                try {
                    if (stream.markSupported()) {
                        stream.reset();
                    } else {
                        Log.i(TAG, "Input stream doesn't support reset(), abandoning.");
                        this.stream = null;
                    }
                } catch(Exception ex2) {
                    Log.i(TAG, "Extra exception while trying to reset the stream, abandoning.", ex2);
                    this.stream = null;
                }
                throw ex;
            }
            // Even if we're finished, it doesn't mean the request is successful, so it's possible
            // that the request will be retried. Therefore try to reset() the stream and close /
            // nullify it if we're too far past the mark.
            try {
                Log.i(TAG, "Trying to reset the stream after successful reading.");
                if (stream.markSupported()) {
                    stream.reset();
                } else {
                    Log.i(TAG, "Input stream doesn't support reset(), abandoning.");
                    this.stream = null;
                }
            } catch (IOException ex) {
                Log.i(TAG, "Failed to reset the stream, abandoning.", ex);
                this.stream = null;
            }
        }
    }

    private void put(String url, RequestBody requestBody) throws IOException {
        put(url, requestBody, new Headers.Builder().build());
    }

    private void put(String url, RequestBody requestBody, Headers headers) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .put(requestBody)
                .headers(headers)
                .build();
        execute(request);
    }

    @Override
    public void delete(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .delete()
                .build();
        execute(request);
    }

    @Override
    public void createDirectory(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .method("MKCOL", null)
                .build();
        execute(request);
    }

    @Override
    public void move(String sourceUrl, String destinationUrl) throws IOException {
        move(sourceUrl, destinationUrl, true);
    }

    @Override
    public void move(String sourceUrl, String destinationUrl, boolean overwrite) throws IOException {
        move(sourceUrl, destinationUrl, overwrite, null);
    }

    @Override
    public void move(String sourceUrl, String destinationUrl, boolean overwrite, String lockToken) throws IOException {
        Request.Builder builder = new Request.Builder()
                .url(sourceUrl)
                .method("MOVE", null);

        Headers.Builder headersBuilder = new Headers.Builder();
        headersBuilder.add("DESTINATION", URI.create(destinationUrl).toASCIIString());
        headersBuilder.add("OVERWRITE", overwrite ? "T" : "F");

        if (lockToken != null) {
            addLockTokenToHeaders(headersBuilder, destinationUrl, lockToken);
        }
        builder.headers(headersBuilder.build());
        Request request = builder.build();
        execute(request);
    }

    private void addLockTokenToHeaders(Headers.Builder headersBuilder, String destinationUrl, String lockToken) {
        headersBuilder.add("If", "<" + destinationUrl + "> (<" + lockToken + ">)");
    }

    @Override
    public void copy(String sourceUrl, String destinationUrl) throws IOException {
        copy(sourceUrl, destinationUrl, true);
    }

    @Override
    public void copy(String sourceUrl, String destinationUrl, boolean overwrite) throws IOException {
        Request request = new Request.Builder()
                .url(sourceUrl)
                .method("COPY", null)
                .header("DESTINATION", URI.create(destinationUrl).toASCIIString())
                .header("OVERWRITE", overwrite ? "T" : "F")
                .build();
        execute(request);
    }

    @Override
    public boolean exists(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", "0")
                .method("PROPFIND", null)
                .build();

        return execute(request, new ExistsResponseHandler());
    }

    @Override
    public String lock(String url) throws IOException {
        return lock(url, 0);
    }

    @Override
    public String lock(String url, int timeout) throws IOException {
        Lockinfo body = new Lockinfo();
        Lockscope scopeType = new Lockscope();
        scopeType.setExclusive(new Exclusive());
        body.setLockscope(scopeType);
        Locktype lockType = new Locktype();
        lockType.setWrite(new Write());
        body.setLocktype(lockType);

        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));

        Request.Builder builder = new Request.Builder()
                .url(url)
                .method("LOCK", requestBody);
        if (timeout > 0) {
            builder.header("Timeout", "Second-" + timeout);
        }
        Request request = builder.build();
        return execute(request, new LockResponseHandler());
    }

    @Override
    public String refreshLock(String url, String token, String file) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .method("LOCK", null)
                .header("If", "<" + file + "> (<" + token + ">)")
                .build();
        return execute(request, new LockResponseHandler());
    }

    @Override
    public void unlock(String url, String token) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .method("UNLOCK", null)
                .header("Lock-Token", "<" + token + ">")
                .build();

        execute(request, new VoidResponseHandler());
    }

    @Override
    public DavAcl getAcl(String url) throws IOException {
        Propfind body = new Propfind();
        Prop prop = new Prop();
        prop.setOwner(new Owner());
        prop.setGroup(new Group());
        prop.setAcl(new Acl());
        body.setProp(prop);

        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", "0")
                .method("PROPFIND", requestBody)
                .build();

        Multistatus multistatus = this.execute(request, new MultiStatusResponseHandler());
        List<com.thegrizzlylabs.sardineandroid.model.Response> responses = multistatus.getResponse();
        if (responses.isEmpty()) {
            return null;
        } else {
            return new DavAcl(responses.get(0));
        }
    }

    @Override
    public DavQuota getQuota(String url) throws IOException {
        Propfind body = new Propfind();
        Prop prop = new Prop();
        prop.setQuotaAvailableBytes(new QuotaAvailableBytes());
        prop.setQuotaUsedBytes(new QuotaUsedBytes());
        body.setProp(prop);

        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", "0")
                .method("PROPFIND", requestBody)
                .build();

        Multistatus multistatus = this.execute(request, new MultiStatusResponseHandler());
        List<com.thegrizzlylabs.sardineandroid.model.Response> responses = multistatus.getResponse();
        if (responses.isEmpty()) {
            return null;
        } else {
            return new DavQuota(responses.get(0));
        }
    }

    @Override
    public void setAcl(String url, List<DavAce> aces) throws IOException {
        // Build WebDAV <code>ACL</code> entity.
        Acl body = new Acl();
        body.setAce(new ArrayList<Ace>());
        for (DavAce davAce : aces) {
            // protected and inherited acl must not be part of ACL http request
            if (davAce.getInherited() != null || davAce.isProtected()) {
                continue;
            }
            Ace ace = davAce.toModel();
            body.getAce().add(ace);
        }
        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .method("ACL", requestBody)
                .build();

        this.execute(request, new VoidResponseHandler());
    }

    @Override
    public List<DavPrincipal> getPrincipals(String url) throws IOException {
        Propfind body = new Propfind();
        Prop prop = new Prop();
        /*prop.setDisplayname(new Displayname());
        prop.setResourcetype(new Resourcetype());
        prop.setPrincipalURL(new PrincipalURL());*/
        body.setProp(prop);

        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", "1")
                .method("PROPFIND", requestBody)
                .build();

        Multistatus multistatus = this.execute(request, new MultiStatusResponseHandler());
        List<com.thegrizzlylabs.sardineandroid.model.Response> responses = multistatus.getResponse();
        if (responses.isEmpty()) {
            return null;
        } else {
            List<DavPrincipal> collections = new ArrayList<>();
            for (com.thegrizzlylabs.sardineandroid.model.Response r : responses) {
                if (r.getPropstat() != null) {
                    for (Propstat propstat : r.getPropstat()) {
                        if (propstat.getProp() != null
                                && propstat.getProp().getResourcetype() != null
                                && propstat.getProp().getResourcetype().getPrincipal() != null) {
                            collections.add(new DavPrincipal(DavPrincipal.PrincipalType.HREF,
                                    r.getHref()/*.get(0)*/,
                                    propstat.getProp().getDisplayname()/*.getContent().get(0)*/));
                        }
                    }
                }
            }
            return collections;
        }
    }

    @Override
    public List<String> getPrincipalCollectionSet(String url) throws IOException {
        Propfind body = new Propfind();
        Prop prop = new Prop();
        prop.setPrincipalCollectionSet(new PrincipalCollectionSet());
        body.setProp(prop);

        RequestBody requestBody = RequestBody.create(MediaType.parse("text/xml"), SardineUtil.toXml(body));
        Request request = new Request.Builder()
                .url(url)
                .header("Depth", "0")
                .method("PROPFIND", requestBody)
                .build();

        Multistatus multistatus = execute(request, new MultiStatusResponseHandler());
        List<com.thegrizzlylabs.sardineandroid.model.Response> responses = multistatus.getResponse();
        if (responses.isEmpty()) {
            return null;
        } else {
            List<String> collections = new ArrayList<>();
            for (com.thegrizzlylabs.sardineandroid.model.Response r : responses) {
                if (r.getPropstat() != null) {
                    for (Propstat propstat : r.getPropstat()) {
                        if (propstat.getProp() != null
                                && propstat.getProp().getPrincipalCollectionSet() != null
                                && propstat.getProp().getPrincipalCollectionSet().getHref() != null) {
                            collections.add(propstat.getProp().getPrincipalCollectionSet().getHref());
                        }
                    }
                }
            }
            return collections;
        }
    }

    @Override
    public void enableCompression() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void disableCompression() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void ignoreCookies() {
        throw new UnsupportedOperationException();
    }
    private void execute(Request request) throws IOException {
        execute(request, new VoidResponseHandler());
    }

    private <T> T execute(Request request, ResponseHandler<T> responseHandler) throws IOException {
        Response response = client.newCall(request).execute();
        return responseHandler.handleResponse(response);
    }

}
