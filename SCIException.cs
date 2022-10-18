using System;

/**
 * All exceptions thrown by SCIClient are subclasses of this exception.
 * They may be encapsulating other Java exceptions, or be a string message.
 * If they are an error message direct from the SCI server they will be of
 * type SCIServerError. These must be displayed to the user.
 */
namespace com.sitemorse.sci
{

    public class SCIException : Exception
    {
        private static long serialVersionUID = 8955498931115729307L;

        public SCIException(Exception e)
            : base("SCIException: " + e.Message, e)
        {
        }


        public SCIException(String message) :
            base(message) { }
    }
}
