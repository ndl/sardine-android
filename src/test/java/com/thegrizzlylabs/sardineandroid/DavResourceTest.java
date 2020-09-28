/*
 * Copyright 2009-2011 Jon Stevens et al.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.thegrizzlylabs.sardineandroid;

import org.junit.Test;

import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 */
public class DavResourceTest
{
	@Test
	public void testGetCreation() throws Exception
	{
		final Date creation = new Date();
		DavResource folder = new DavResource.Builder("/test/path/").createdOn(creation).build();
		assertEquals(creation, folder.getCreation());
	}

	@Test
	public void testGetModified() throws Exception
	{
		final Date modified = new Date();
		DavResource folder = new DavResource.Builder("/test/path/").modifiedOn(modified).build();
		assertEquals(modified, folder.getModified());
	}

	@Test
	public void testGetContentType() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").ofType("httpd/unix-directory").build();
		assertEquals("httpd/unix-directory", folder.getContentType());
	}

	@Test
	public void testGetContentLength() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").ofLength(3423L).build();
		assertEquals(new Long(3423), folder.getContentLength());
	}

	@Test
	public void testGetContentLanguage() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").inLanguage("en_us").build();
		assertEquals("en_us", folder.getContentLanguage());
	}

	@Test
	public void testDisplayname() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").withDisplayName("My path").build();
		assertEquals("My path", folder.getDisplayName());
	}

	@Test
	public void testResourcetype() throws Exception
	{
		List<QName> types = Arrays.asList(new QName("namespace", "tag"), new QName("namespace", "othertag"));
		DavResource folder = new DavResource.Builder("/test/path/").withResourceTypes(types).build();
		assertEquals(types, folder.getResourceTypes());
	}

	@Test
	public void testIsDirectory() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").ofType("httpd/unix-directory").build();
		assertTrue(folder.isDirectory());
	}

	@Test
	public void testGetCustomProps() throws Exception
	{
        {
            DavResource file = new DavResource.Builder("/test/path/file.html").ofLength(6587L)
					.withCustomProps(Collections.<QName, String>singletonMap(
							new QName("http://mynamespace", "property", "my"), "custom")).build();
            assertNotNull(file.getCustomProps());
            assertEquals(file.getCustomProps(), Collections.singletonMap("property", "custom"));
            assertEquals(file.getCustomPropsNS(), Collections.singletonMap(
                    new QName("http://mynamespace", "property", "my"), "custom"));
        }
	}

	@Test
	public void testGetName() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").build();
		assertEquals("path", folder.getName());
		DavResource file = new DavResource.Builder("/test/path/file.html").ofLength(6587L).build();
		assertEquals("file.html", file.getName());
	}

	@Test
	public void testGetPath() throws Exception
	{
		DavResource folder = new DavResource.Builder("/test/path/").build();
		assertEquals("/test/path/", folder.getPath());
		DavResource file = new DavResource.Builder("/test/path/file.html").ofLength(6587L).build();
		assertEquals("/test/path/file.html", file.getPath());
	}

	@Test
	public void testFullyQualifiedHref() throws Exception
	{
		{
			DavResource folder = new DavResource.Builder("/test/path/").ofType("httpd/unix-directory").ofLength(3423L).build();
			assertEquals("/test/path/", folder.getPath());
		}
		{
			DavResource folder = new DavResource.Builder("http://example.net/test/path/").ofType("httpd/unix-directory")
					.ofLength(3423L).build();
			assertEquals("/test/path/", folder.getPath());
		}
	}

	@Test
	public void testUriEncoding() throws Exception
	{
		{
			DavResource resource = new DavResource.Builder("http://example.net/path/%C3%A4%C3%B6%C3%BC/")
					.ofType("httpd/unix-directory").ofLength(3423L).build();
			assertEquals("/path/äöü/", resource.getPath());
			assertEquals("/path/%C3%A4%C3%B6%C3%BC/", resource.getHref().getRawPath());
		}
		{
			DavResource resource = new DavResource.Builder("/Meine%20Anlagen").ofType("httpd/unix-directory").ofLength(0L).build();
			assertEquals("/Meine Anlagen", resource.getPath());
			assertEquals("/Meine%20Anlagen", resource.getHref().getRawPath());
		}
	}
}
