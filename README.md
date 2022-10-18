# Sitemorse CMS Integration (SCI) C# Client

## What is Sitemorse INCMS?
Sitemorse **INCMS** allows you to integrate Sitemorse testing with your applications. It was designed to allow a Content Management System (CMS) to utilise the services provided by Sitemorse, but the API can be used in any application where testing of a web page is required.

Content management systems usually run behind firewalls within an organisation. This makes it difficult to use an external servicem, such as Sitemorse, to test content within the content management system. The Sitemorse **INCMS** module is designed to run behind the firewall within a content management system or other applciation. It establishes an outbound connection to the Sitemorse servers and handles all requests from Sitemorse for content to test. From a security point of view, a port needs to be open for outbound connection to Sitemorse. This port is, by default, 5372, but it can be set to any other value.

The protocol used to transfer content to Sitemorse for testing is the Sitemorse CMS Integration (SCI) protocol. This handles authentication and communication with Sitemorse servers. The full specification is available on request from sales@Sitemorse.com.

This is a C# implementation of a client for the SCI protocol and makes it much easier for you to perform Sitemorse tests by just calling the client with a licence key and the content to test.

## Licencing
This software is open source but to perform a Sitemorse test requires a valid licence key. A licence key and protocol documentation can be obtained by contacting sales@Sitemorse.com.

## Example C# code

## Nuget
A nuspec is provided should you want to create a nuget package. This is also available as a package in the [Nuget Gallery](https://www.nuget.org/packages).

## Other versions
Other versions of this client are available in [php](https://github.com/sitemorse/sci-php) and [java](https://github.com/sitemorse/sci-java).