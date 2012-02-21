<?php

header("Content-Type: text/xml; charset=utf-8");
header("Cache-Control: no-cache, must-revalidate");
$url = 'http://feed.c22.cc/rss?ref=' . rand(0, 9999);

function file_get_contents_utf8($fn) {
        $opts = array(
                'http' => array(
                        'method'=>"GET",
                        'header'=>"Content-Type: text/html; charset=utf-8"
                )
        );

        $context = stream_context_create($opts);
        $result = @file_get_contents($fn,false,$context);
        return $result;
}

$tumblr_feed = file_get_contents_utf8($url);
$tumblr_feed = utf8_encode($tumblr_feed);

$doc = new DOMDocument('1.0', 'UTF-8');
$xdoc = new DOMXPath($doc);
$doc->loadXML($tumblr_feed);

$arrFeeds = array();

// Create base RSS

$rssfeed = '<?xml version="1.0" encoding="UTF-8"?>';
$rssfeed .= '<rss xmlns:dc="http://purl.org/dc/elements/1.1/" version="2.0">';
$rssfeed .= '     <channel>';
$rssfeed .= '       <atom:link rel="hub" href="http://feed.c22.cc" xmlns:atom="http://www.w3.org/2005/Atom"/>';
$rssfeed .= '        <title>Shared Reader RSS feed</title>';
$rssfeed .= '        <description>Shared Items Feed</description>';
$rssfeed .= '        <link>http://blog.c22.cc/</link>';

foreach ($doc->getElementsByTagName('item') as $node) {
    $text = $node->getElementsByTagName('description')->item(0)->nodeValue;
    $reg_exUrl = '/<a href="(.*?)">/i';

    if(preg_match($reg_exUrl, $text, $realurl)) {
       // make the urls hyper links
       $replace = $realurl[1];
       //die();
    } else {
       // if no urls in the text just return the text
       $repalce = $node->getElementsByTagName('link')->item(0)->nodeValue;
    }

    $itemRSS = array (
        'title' => $node->getElementsByTagName('title')->item(0)->nodeValue,
        'desc' => $node->getElementsByTagName('description')->item(0)->nodeValue,
        'link' => $replace,
        'guid' => $replace,
        'date' => $node->getElementsByTagName('pubDate')->item(0)->nodeValue
        );
    array_push($arrFeeds, $itemRSS);

    $title_enc = htmlspecialchars($itemRSS['title'], ENT_QUOTES, 'UTF-8', false);
    $desc_enc = htmlspecialchars($itemRSS['desc'], ENT_QUOTES, 'UTF-8', false);
    $link_enc = htmlspecialchars($itemRSS['link'], ENT_QUOTES, 'UTF-8', false);
    $guid_enc = htmlspecialchars($itemRSS['guid'], ENT_QUOTES, 'UTF-8', false);

    $rssfeed .= '        <item>';
    $rssfeed .= '            <title>' . $title_enc .'</title>';
    $rssfeed .= '            <description>' . $desc_enc .'</description>';
    $rssfeed .= '            <link>' . $link_enc .'</link>';
    $rssfeed .= '            <guid>' . $guid_enc .'</guid>';
    $rssfeed .= '            <pubDate>' . $itemRSS['date'] .'</pubDate>';
    $rssfeed .= '        </item>';

    }

$rssfeed .= '    </channel>';
$rssfeed .= '  </rss>';

echo $rssfeed

?>
