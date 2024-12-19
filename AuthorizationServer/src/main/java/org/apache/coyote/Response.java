package org.apache.coyote;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.B2CConverter;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.parser.MediaType;
import org.apache.tomcat.util.res.StringManager;

import jakarta.servlet.WriteListener;

public final class Response {

    private static final StringManager sm = StringManager.getManager(Response.class);
    private static final Log log = LogFactory.getLog(Response.class);
    private static final Locale DEFAULT_LOCALE = Locale.getDefault();
    int status = 200;
    String message = null;
    final MimeHeaders headers = new MimeHeaders();
    private Supplier<Map<String,String>> trailerFieldsSupplier = null;
    OutputBuffer outputBuffer;
    final Object notes[] = new Object[Constants.MAX_NOTES];
    volatile boolean committed = false;
    volatile ActionHook hook;
    String contentType = null;
    String contentLanguage = null;
    Charset charset = null;
    String characterEncoding = null;
    long contentLength = -1;
    private Locale locale = DEFAULT_LOCALE;
    private long contentWritten = 0;
    private long commitTimeNanos = -1;
    private Exception errorException = null;
    private final AtomicInteger errorState = new AtomicInteger(0);
    Request req;

    public Request getRequest() {
        return req;
    }

    public void setRequest(Request req) {
        this.req = req;
    }

    public void setOutputBuffer(OutputBuffer outputBuffer) {
        this.outputBuffer = outputBuffer;
    }

    public MimeHeaders getMimeHeaders() {
        return headers;
    }

    protected void setHook(ActionHook hook) {
        this.hook = hook;
    }

    public void setNote(int pos, Object value) {
        notes[pos] = value;
    }

    public Object getNote(int pos) {
        return notes[pos];
    }

    public void action(ActionCode actionCode, Object param) {
        if (hook != null) {
            if (param == null) {
                hook.action(actionCode, this);
            } else {
                hook.action(actionCode, param);
            }
        }
    }

    public int getStatus() {
        return status;
    }
    
    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isCommitted() {
        return committed;
    }

    public void setCommitted(boolean v) {
        if (v && !this.committed) {
            this.commitTimeNanos = System.nanoTime();
        }
        this.committed = v;
    }

    public long getCommitTime() {
        return System.currentTimeMillis() - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - commitTimeNanos);
    }

    public long getCommitTimeNanos() {
        return commitTimeNanos;
    }

    public void setErrorException(Exception ex) {
        if (errorException == null) {
            errorException = ex;
        }
    }

    public Exception getErrorException() {
        return errorException;
    }

    public boolean isExceptionPresent() {
        return errorException != null;
    }

    @Deprecated
    public boolean setError() {
        return errorState.compareAndSet(0, 1);
    }

    public boolean isError() {
        return errorState.get() > 0;
    }

    public boolean isErrorReportRequired() {
        return errorState.get() == 1;
    }

    public boolean setErrorReported() {
        return errorState.compareAndSet(1, 2);
    }

    public void resetError() {
        errorState.set(0);
    }

    public void reset() throws IllegalStateException {
        if (committed) {
            throw new IllegalStateException();
        }
        recycle();
    }

    public boolean containsHeader(String name) {
        return headers.getHeader(name) != null;
    }

    public void setHeader(String name, String value) {
        char cc = name.charAt(0);
        if (cc == 'C' || cc == 'c') {
            if (checkSpecialHeader(name, value)) {
                return;
            }
        }
        headers.setValue(name).setString(value);
    }

    public void addHeader(String name, String value) {
        addHeader(name, value, null);
    }

    public void addHeader(String name, String value, Charset charset) {
        char cc = name.charAt(0);
        if (cc == 'C' || cc == 'c') {
            if (checkSpecialHeader(name, value)) {
                return;
            }
        }
        MessageBytes mb = headers.addValue(name);
        if (charset != null) {
            mb.setCharset(charset);
        }
        mb.setString(value);
    }

    public void setTrailerFields(Supplier<Map<String,String>> supplier) {
        AtomicBoolean trailerFieldsSupported = new AtomicBoolean(false);
        action(ActionCode.IS_TRAILER_FIELDS_SUPPORTED, trailerFieldsSupported);
        if (!trailerFieldsSupported.get()) {
            throw new IllegalStateException(sm.getString("response.noTrailers.notSupported"));
        }

        this.trailerFieldsSupplier = supplier;
    }

    public Supplier<Map<String,String>> getTrailerFields() {
        return trailerFieldsSupplier;
    }

    private boolean checkSpecialHeader(String name, String value) {
        if (name.equalsIgnoreCase("Content-Type")) {
            setContentType(value);
            return true;
        }
        if (name.equalsIgnoreCase("Content-Length")) {
            try {
                long cL = Long.parseLong(value);
                setContentLength(cL);
                return true;
            } catch (NumberFormatException ex) {
                return false;
            }
        }
        return false;
    }

    @Deprecated
    public void sendHeaders() {
        commit();
    }

    public void commit() {
        action(ActionCode.COMMIT, this);
        setCommitted(true);
    }

    public Locale getLocale() {
        return locale;
    }

    public void setLocale(Locale locale) {
        if (locale == null) {
            this.locale = null;
            this.contentLanguage = null;
            return;
        }
        this.locale = locale;
        contentLanguage = locale.toLanguageTag();
    }

    public String getContentLanguage() {
        return contentLanguage;
    }

    public void setCharacterEncoding(String characterEncoding) throws UnsupportedEncodingException {
        if (isCommitted()) {
            return;
        }
        if (characterEncoding == null) {
            this.charset = null;
            this.characterEncoding = null;
            return;
        }
        this.characterEncoding = characterEncoding;
        this.charset = B2CConverter.getCharset(characterEncoding);
    }

    public Charset getCharset() {
        return charset;
    }

    public String getCharacterEncoding() {
        return characterEncoding;
    }

    public void setContentType(String type) {

        if (type == null) {
            this.contentType = null;
            return;
        }
        MediaType m = null;
	        try {
	            m = MediaType.parseMediaType(new StringReader(type));
	        } catch (IOException e) {
        }
        if (m == null) {
            this.contentType = type;
            return;
        }

        this.contentType = m.toStringNoCharset();
        String charsetValue = m.getCharset();

        if (charsetValue == null) {
            this.contentType = type;
        } else {
            this.contentType = m.toStringNoCharset();
            charsetValue = charsetValue.trim();
            if (charsetValue.length() > 0) {
                try {
                    charset = B2CConverter.getCharset(charsetValue);
                } catch (UnsupportedEncodingException e) {
                    log.warn(sm.getString("response.encoding.invalid", charsetValue), e);
                }
            }
        }
    }

    public void setContentTypeNoCharset(String type) {
        this.contentType = type;
    }

    public String getContentType() {
        String ret = contentType;

        if (ret != null && charset != null) {
            ret = ret + ";charset=" + characterEncoding;
        }
        return ret;
    }

    public void setContentLength(long contentLength) {
        this.contentLength = contentLength;
    }

    public int getContentLength() {
        long length = getContentLengthLong();

        if (length < Integer.MAX_VALUE) {
            return (int) length;
        }
        return -1;
    }

    public long getContentLengthLong() {
        return contentLength;
    }

    public void doWrite(ByteBuffer chunk) throws IOException {
        int len = chunk.remaining();
        outputBuffer.doWrite(chunk);
        contentWritten += len - chunk.remaining();
    }

    public void recycle() {
        contentType = null;
        contentLanguage = null;
        locale = DEFAULT_LOCALE;
        charset = null;
        characterEncoding = null;
        contentLength = -1;
        status = 200;
        message = null;
        committed = false;
        commitTimeNanos = -1;
        errorException = null;
        resetError();
        headers.recycle();
        trailerFieldsSupplier = null;
        listener = null;
        synchronized (nonBlockingStateLock) {
            fireListener = false;
            registeredForWrite = false;
        }

        contentWritten = 0;
    }

    public long getContentWritten() {
        return contentWritten;
    }

    public long getBytesWritten(boolean flush) {
        if (flush) {
            action(ActionCode.CLIENT_FLUSH, this);
        }
        return outputBuffer.getBytesWritten();
    }

    volatile WriteListener listener;
    private boolean fireListener = false;
    private boolean registeredForWrite = false;
    private final Object nonBlockingStateLock = new Object();

    public WriteListener getWriteListener() {
        return listener;
    }

    public void setWriteListener(WriteListener listener) {
        if (listener == null) {
            throw new NullPointerException(sm.getString("response.nullWriteListener"));
        }
        if (getWriteListener() != null) {
            throw new IllegalStateException(sm.getString("response.writeListenerSet"));
        }
        AtomicBoolean result = new AtomicBoolean(false);
        action(ActionCode.ASYNC_IS_ASYNC, result);
        if (!result.get()) {
            throw new IllegalStateException(sm.getString("response.notAsync"));
        }

        this.listener = listener;
        if (isReady()) {
            synchronized (nonBlockingStateLock) {
                registeredForWrite = true;
                fireListener = true;
            }
            action(ActionCode.DISPATCH_WRITE, null);
            if (!req.isRequestThread()) {
                action(ActionCode.DISPATCH_EXECUTE, null);
            }
        }
    }

    public boolean isReady() {
        if (listener == null) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("response.notNonBlocking"));
            }
            return false;
        }
        boolean ready = false;
        synchronized (nonBlockingStateLock) {
            if (registeredForWrite) {
                fireListener = true;
                return false;
            }
            ready = checkRegisterForWrite();
            fireListener = !ready;
        }
        return ready;
    }

    public boolean checkRegisterForWrite() {
        AtomicBoolean ready = new AtomicBoolean(false);
        synchronized (nonBlockingStateLock) {
            if (!registeredForWrite) {
                action(ActionCode.NB_WRITE_INTEREST, ready);
                registeredForWrite = !ready.get();
            }
        }
        return ready.get();
    }

    public void onWritePossible() throws IOException {
        boolean fire = false;
        synchronized (nonBlockingStateLock) {
            registeredForWrite = false;
            if (fireListener) {
                fireListener = false;
                fire = true;
            }
        }
        if (fire) {
            listener.onWritePossible();
        }
    }
}
