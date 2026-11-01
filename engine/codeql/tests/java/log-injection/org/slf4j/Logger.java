package org.slf4j; public interface Logger {
void info(String message); void info(String format, Object value); void info(String format, Object first, Object second); void info(String format, Object... values);
void info(Marker marker, String message); void info(Marker marker, String format, Object value);
}
