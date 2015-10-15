#pragma once

#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/optional.hpp>
#include <boost/regex.hpp>

namespace uap
{

// std::regex implementation is insanely slow, so use boost::regex for now.
namespace RegexImpl = ::boost;

struct UaParser
{
public:
    struct Result
    {
        std::string browserName;
        std::string browserUnit;
        std::string browserVersion;
        std::string cpuArchitecture;
        std::string deviceType;
        std::string deviceModel;
        std::string deviceVendor;
        std::string engineName;
        std::string engineVersion;
        std::string osName;
        std::string osVersion;
    };

    Result parse(const std::string& ua) const
    {
        auto result = Result();

        for (const auto matcherGroup : getMatcherGroups())
        {
            for (const auto matcher : matcherGroup)
            {
                if (matcher(ua, result))
                {
                    break;
                }
            }
        }

        return result;
    }

private:
    struct Matcher;
    using MatcherGroup = std::vector<Matcher>;

    const std::vector<MatcherGroup>& getMatcherGroups() const
    {
        using RegexImpl::regex;

        static const auto CONSOLE = "console";
        // TODO: static const auto DESKTOP = "desktop";
        static const auto MOBILE = "mobile";
        static const auto SMARTTV = "smarttv";
        static const auto TABLET = "tablet";
        static const auto WEARABLE = "wearable";
        static const auto i = regex::ECMAScript | regex::icase;
        static const auto regexes = std::vector<MatcherGroup>{
            {
                // browser
                {{
                     // Presto based
                     regex{"(opera\\smini)\\/([\\w\\.-]+)", i},                  // Opera Mini
                     regex{"(opera\\s[mobiletab]+).+version\\/([\\w\\.-]+)", i}, // Opera Mobi/Tablet
                     regex{"(opera).+version\\/([\\w\\.]+)", i},                 // Opera > 9.80
                     regex{"(opera)[\\/\\s]+([\\w\\.]+)", i},                    // Opera < 9.80

                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"\\s(opr)\\/([\\w\\.]+)", i}, // Opera Webkit
                 },
                 {
                     {&Result::browserName, "Opera"},
                     {&Result::browserVersion},
                 }},
                {{
                     // Mixed
                     regex{"(kindle)\\/([\\w\\.]+)", i},                                           // Kindle
                     regex{"(lunascape|maxthon|netfront|jasmine|blazer)[\\/\\s]?([\\w\\.]+)*", i}, // Lunascape/Maxthon/Netfront/Jasmine/Blazer
                     // Trident based
                     regex{"(avant\\s|iemobile|slim|baidu)(?:browser)?[\\/\\s]?([\\w\\.]*)", i}, // Avant/IEMobile/SlimBrowser/Baidu
                     regex{"(?:ms|\\()(ie)\\s([\\w\\.]+)", i},                                   // Internet Explorer
                     // Webkit/KHTML based
                     regex{"(rekonq)\\/([\\w\\.]+)*", i},                                                                                    // Rekonq
                     regex{"(chromium|flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium)\\/([\\w\\.-]+)", i}, // Chromium/Flock/RockMelt/Midori/Epiphany/Silk/Skyfire/Bolt/Iron/Iridium
                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(trident).+rv[:\\s]([\\w\\.]+).+like\\sgecko", i}, // IE11
                 },
                 {
                     {&Result::browserName, "IE"},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(edge)\\/((\\d+)?[\\w\\.]+)", i}, // Microsoft Edge
                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(yabrowser)\\/([\\w\\.]+)", i}, // Yandex
                 },
                 {
                     {&Result::browserName, "Yandex"},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(comodo_dragon)\\/([\\w\\.]+)", i}, // Comodo Dragon
                 },
                 {
                     {&Result::browserName, FnReplace{'_', ' '}},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(chrome|omniweb|arora|[tizenoka]{5}\\s?browser)\\/v?([\\w\\.]+)", i}, // Chrome/OmniWeb/Arora/Tizen/Nokia
                     regex{"(qqbrowser)[\\/\\s]?([\\w\\.]+)", i},                                 // QQBrowser
                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(uc\\s?browser)[\\/\\s]?([\\w\\.]+)", i}, // UCBrowser
                     regex{"ucweb.+(ucbrowser)[\\/\\s]?([\\w\\.]+)", i},
                     regex{"JUC.+(ucweb)[\\/\\s]?([\\w\\.]+)", i},
                 },
                 {
                     {&Result::browserName, "UCBrowser"},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"(dolfin)\\/([\\w\\.]+)", i}, // Dolphin
                 },
                 {
                     {&Result::browserName, "Dolphin"},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"((?:android.+)crmo|crios)\\/([\\w\\.]+)", i}, // Chrome for Android/iOS
                 },
                 {
                     {&Result::browserName, "Chrome"},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"XiaoMi\\/MiuiBrowser\\/([\\w\\.]+)", i}, // MIUI Browser
                 },
                 {{&Result::browserVersion},
                  {&Result::browserName, "MIUI Browser"}}},
                {{
                     regex{"android.+version\\/([\\w\\.]+)\\s+(?:mobile\\s?safari|safari)", i}, // Android Browser
                 },
                 {
                     {&Result::browserVersion},
                     {&Result::browserName, "Android Browser"},
                 }},
                {{
                     regex{"FBAV\\/([\\w\\.]+);", i}, // Facebook App for iOS
                 },
                 {
                     {&Result::browserVersion},
                     {&Result::browserName, "Facebook"},
                 }},
                {{
                     regex{"version\\/([\\w\\.]+).+?mobile\\/\\w+\\s(safari)", i}, // Mobile Safari
                 },
                 {
                     {&Result::browserVersion},
                     {&Result::browserName, "Mobile Safari"},
                 }},
                {{
                     regex{"version\\/([\\w\\.]+).+?(mobile\\s?safari|safari)", i}, // Safari & Safari Mobile
                 },
                 {
                     {&Result::browserVersion},
                     {&Result::browserName},
                 }},
                {{
                     regex{"webkit.+?(mobile\\s?safari|safari)(\\/[\\w\\.]+)", i}, // Safari < 3.0
                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion, FnFixSafariVersion{}},
                 }},
                {{
                     regex{"(konqueror)\\/([\\w\\.]+)", i}, // Konqueror
                     regex{"(webkit|khtml)\\/([\\w\\.]+)", i},
                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion},
                 }},
                {{
                     // Gecko based
                     regex{"(navigator|netscape)\\/([\\w\\.-]+)", i}, // Netscape
                 },
                 {
                     {&Result::browserName, "Netscape"},
                     {&Result::browserVersion},
                 }},
                {{
                     regex{"fxios\\/([\\w\\.-]+)", i}, // Firefox for iOS
                 },
                 {
                     {&Result::browserVersion},
                     {&Result::browserName, "Firefox"},
                 }},
                {{
                     regex{"(swiftfox)", i},                                                                                         // Swiftfox
                     regex{"(icedragon|iceweasel|camino|chimera|fennec|maemo\\sbrowser|minimo|conkeror)[\\/\\s]?([\\w\\.\\+]+)", i}, // IceDragon/Iceweasel/Camino/Chimera/Fennec/Maemo/Minimo/Conkeror
                     regex{"(firefox|seamonkey|k-meleon|icecat|iceape|firebird|phoenix)\\/([\\w\\.-]+)", i},                         // Firefox/SeaMonkey/K-Meleon/IceCat/IceApe/Firebird/Phoenix
                     regex{"(mozilla)\\/([\\w\\.]+).+rv\\:.+gecko\\/\\d+", i},                                                       // Mozilla
                     // Other
                     regex{"(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf)[\\/\\s]?([\\w\\.]+)", i}, // Polaris/Lynx/Dillo/iCab/Doris/Amaya/w3m/NetSurf
                     regex{"(links)\\s\\(([\\w\\.]+)", i},                                              // Links
                     regex{"(gobrowser)\\/?([\\w\\.]+)*", i},                                           // GoBrowser
                     regex{"(ice\\s?browser)\\/v?([\\w\\._]+)", i},                                     // ICE Browser
                     regex{"(mosaic)[\\/\\s]([\\w\\.]+)", i},                                           // Mosaic
                 },
                 {
                     {&Result::browserName},
                     {&Result::browserVersion},
                 }},
            },
            {
                // cpu
                {{
                     regex{"(?:(amd|x(?:(?:86|64)[_-])?|wow|win)64)[;\\)]", i}, // AMD64
                 },
                 {{&Result::cpuArchitecture, "amd64"}}},
                {{
                     regex{"(ia32(?=;))", i}, // IA32 (quicktime)
                 },
                 {{&Result::browserVersion, FnToLower{}}}},
                {{
                     regex{"((?:i[346]|x)86)[;\\)]", i}, // IA32
                 },
                 {{&Result::cpuArchitecture, "ia32"}}},
                {{
                     // PocketPC mistakenly identified as PowerPC
                     regex{"windows\\s(ce|mobile);\\sppc;", i},
                 },
                 {{&Result::cpuArchitecture, "arm"}}},
                {{
                     regex{"((?:ppc|powerpc)(?:64)?)(?:\\smac|;|\\))", i}, // PowerPC
                     // TODO ], [[ARCHITECTURE, /ower/, '', util.lowerize]], [
                 },
                 {{&Result::cpuArchitecture, FnToLower{}}}},
                {{
                     regex{"(sun4\\w)[;\\)]", i}, // SPARC
                 },
                 {{&Result::cpuArchitecture, "sparc"}}},
                {{
                     // IA64, 68K, ARM/64, AVR/32, IRIX/64, MIPS/64, SPARC/64, PA-RISC
                     regex{"((?:avr32|ia64(?=;))|68k(?=\\))|arm(?:64|(?=v\\d+;))|(?=atmel\\s)avr|(?:irix|mips|sparc)(?:64)?(?=;)|pa-risc)", i},
                 },
                 {{&Result::cpuArchitecture, FnToLower{}}}},
            },
            {
                // device
                {{
                     regex{"\\((ipad|playbook);[\\w\\s\\);-]+(rim|apple)", i}, // iPad/PlayBook
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"applecoremedia\\/[\\w\\.]+ \\((ipad)"}, // iPad
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Apple"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(apple\\s{0,1}tv)", i}, // Apple TV
                 },
                 {
                     {&Result::deviceModel, "Apple TV"},
                     {&Result::deviceVendor, "Apple"},
                 }},
                {{
                     regex{"(archos)\\s(gamepad2?)", i},              // Archos
                     regex{"(hp).+(touchpad)", i},                    // HP TouchPad
                     regex{"(kindle)\\/([\\w\\.]+)", i},              // Kindle
                     regex{"\\s(nook)[\\w\\s]+build\\/(\\w+)", i},    // Nook
                     regex{"(dell)\\s(strea[kpr\\s\\d]*[\\dko])", i}, // Dell Streak
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(kf[A-z]+)\\sbuild\\/[\\w\\.]+.*silk\\/", i}, // Kindle Fire HD
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Amazon"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(sd|kf)[0349hijorstuw]+\\sbuild\\/[\\w\\.]+.*silk\\/", i}, // Fire Phone
                 },
                 {
                     {&Result::deviceModel, FnFixAmazonDeviceModel{}},
                     {&Result::deviceVendor, "Amazon"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"\\((ip[honed|\\s\\w*]+);.+(apple)", i}, // iPod/iPhone
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"\\((ip[honed|\\s\\w*]+);", i}, // iPod/iPhone
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Apple"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"(blackberry)[\\s-]?(\\w+)", i},                                                                                  // BlackBerry
                     regex{"(blackberry|benq|palm(?=\\-)|sonyericsson|acer|asus|dell|huawei|meizu|motorola|polytron)[\\s_-]?([\\w-]+)*", i}, // BenQ/Palm/Sony-Ericsson/Acer/Asus/Dell/Huawei/Meizu/Motorola/Polytron
                     regex{"(hp)\\s([\\w\\s]+\\w)", i},                                                                                      // HP iPAQ
                     regex{"(asus)-?(\\w+)", i},                                                                                             // Asus
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"\\(bb10;\\s(\\w+)", i}, // BlackBerry 10
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "BlackBerry"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"android.+(transfo[prime\\s]{4,10}\\s\\w+|eeepc|slider\\s\\w+|nexus 7)", i}, // Asus Tablets
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Asus"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(sony)\\s(tablet\\s[ps])\\sbuild\\/", i}, // Sony
                     regex{"(sony)?(?:sgp.+)\\sbuild\\/", i},
                 },
                 {
                     {&Result::deviceVendor, "Sony"},
                     {&Result::deviceModel, "Xperia Tablet"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(?:sony)?(?:(?:(?:c|d)\\d{4})|(?:so[-l].+))\\sbuild\\/", i},
                 },
                 {
                     {&Result::deviceVendor, "Sony"},
                     {&Result::deviceModel, "Xperia Phone"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"\\s(ouya)\\s", i},             // Ouya
                     regex{"(nintendo)\\s([wids3u]+)", i}, // Nintendo
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, CONSOLE},
                 }},
                {{
                     regex{"android.+;\\s(shield)\\sbuild", i}, // Nvidia
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Nvidia"},
                     {&Result::deviceType, CONSOLE},
                 }},
                {{
                     regex{"(playstation\\s[3portablevi]+)", i}, // Playstation
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Sony"},
                     {&Result::deviceType, CONSOLE},
                 }},
                {{
                     regex{"(sprint\\s(\\w+))", i}, // Sprint Phones
                 },
                 {
                     {&Result::deviceVendor, FnFixSprintDeviceVendor{}},
                     {&Result::deviceModel, FnFixSprintDeviceModel{}},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"(lenovo)\\s?(S(?:5000|6000)+(?:[-][\\w+]))", i}, // Lenovo tablets
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(htc)[;_\\s-]+([\\w\\s]+(?=\\))|\\w+)*", i},                                            // HTC
                     regex{"(zte)-(\\w+)*", i},                                                                     // ZTE
                     regex{"(alcatel|geeksphone|huawei|lenovo|nexian|panasonic|(?=;\\s)sony)[_\\s-]?([\\w-]+)*", i} // Alcatel/GeeksPhone/Huawei/Lenovo/Nexian/Panasonic/Sony
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel, FnReplace{'_', ' '}},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"(nexus\\s9)", i}, // HTC Nexus 9
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "HTC"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"[\\s\\(;](xbox(?:\\sone)?)[\\s\\);]", i}, // Microsoft Xbox
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Microsoft"},
                     {&Result::deviceType, CONSOLE},
                 }},
                {{
                     regex{"(kin\\.[onetw]{3})", i}, // Microsoft Kin
                 },
                 {
                     {&Result::deviceModel, FnReplace{'.', ' '}},
                     {&Result::deviceVendor, "Microsoft"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"\\s(milestone|droid(?:[2-4x]|\\s(?:bionic|x2|pro|razr))?(:?\\s4g)?)[\\w\\s]+build\\/", i}, // Motorola
                     regex{"mot[\\s-]?(\\w+)*", i},
                     regex{"(XT\\d{3,4}) build\\/", i},
                     regex{"(nexus\\s[6])", i},
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Motorola"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"android.+\\s(mz60\\d|xoom[\\s2]{0,2})\\sbuild\\/", i},
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Motorola"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"android.+((sch-i[89]0\\d|shw-m380s|gt-p\\d{4}|gt-n8000|sgh-t8[56]9|nexus 10))", i}, // Samsung
                     regex{"((SM-T\\w+))", i},
                 },
                 {
                     {&Result::deviceVendor, "Samsung"},
                     {&Result::deviceModel},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"((s[cgp]h-\\w+|gt-\\w+|galaxy\\snexus|sm-n900))", i}, // Samsung
                     regex{"(sam[sung]*)[\\s-]*(\\w+-?[\\w-]*)*", i},
                     regex{"sec-((sgh\\w+))", i},
                 },
                 {
                     {&Result::deviceVendor, "Samsung"},
                     {&Result::deviceModel},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"(samsung);smarttv", i},
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor},
                     {&Result::deviceType, SMARTTV},
                 }},
                {{
                     regex{"\\(dtv[\\);].+(aquos)", i}, // Sharp
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Sharp"},
                     {&Result::deviceType, SMARTTV},
                 }},
                {{
                     regex{"sie-(\\w+)*", i}, // Siemens
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Siemens"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"(maemo|nokia).*(n900|lumia\\s\\d+)", i}, // Nokia
                     regex{"(nokia)[\\s_-]?([\\w-]+)*", i},
                 },
                 {
                     {&Result::deviceVendor, "Nokia"},
                     {&Result::deviceModel},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"android\\s3\\.[\\s\\w;-]{10}(a\\d{3})", i}, // Acer
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Acer"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"android\\s3\\.[\\s\\w;-]{10}(lg?)-([06cv9]{3,4})", i}, // LG Tablet
                 },
                 {
                     {&Result::deviceVendor, "LG"},
                     {&Result::deviceModel},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"(lg) netcast\\.tv", i}, // LG SmartTV
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, SMARTTV},
                 }},
                {{
                     regex{"(nexus\\s[456])", i}, // LG
                     regex{"lg[e;\\s\\/-]+(\\w+)*", i},
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "LG"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"android.+(ideatab[a-z0-9\\-\\s]+)", i}, // Lenovo
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Lenovo"},
                     {&Result::deviceType, TABLET},
                 }},
                {{
                     regex{"linux;.+((jolla));", i}, // Jolla
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"((pebble))app\\/[\\d\\.]+\\s", i}, // Pebble
                 },
                 {
                     {&Result::deviceVendor},
                     {&Result::deviceModel},
                     {&Result::deviceType, WEARABLE},
                 }},
                {{
                     regex{"android.+;\\s(glass)\\s\\d", i}, // Google Glass
                 },
                 {
                     {&Result::deviceModel},
                     {&Result::deviceVendor, "Google"},
                     {&Result::deviceType, WEARABLE},
                 }},
                {{
                     regex{"android.+(\\w+)\\s+build\\/hm\\1", i},                                         // Xiaomi Hongmi 'numeric' models
                     regex{"android.+(hm[\\s\\-_]*note?[\\s_]*(?:\\d\\w)?)\\s+build", i},                  // Xiaomi Hongmi
                     regex{"android.+(mi[\\s\\-_]*(?:one|one[\\s_]plus)?[\\s_]*(?:\\d\\w)?)\\s+build", i}, // Xiaomi Mi
                 },
                 {
                     {&Result::deviceModel, FnReplace{'_', ' '}},
                     {&Result::deviceVendor, "Xiaomi"},
                     {&Result::deviceType, MOBILE},
                 }},
                {{
                     regex{"(mobile|tablet);.+rv\\:.+gecko\\/", i}, // Unidentifiable
                 },
                 {
                     {&Result::deviceType, FnToLower{}},
                     {&Result::deviceVendor, ""},
                     {&Result::deviceModel, ""},
                 }},
            },
            {
                // engine
                {{
                     regex{"windows.+\\sedge\\/([\\w\\.]+)", i}, // EdgeHTML
                 },
                 {
                     {&Result::engineVersion},
                     {&Result::engineName, "EdgeHTML"},
                 }},
                {{
                     regex{"(presto)\\/([\\w\\.]+)", i},                                         // Presto
                     regex{"(webkit|trident|netfront|netsurf|amaya|lynx|w3m)\\/([\\w\\.]+)", i}, // WebKit/Trident/NetFront/NetSurf/Amaya/Lynx/w3m
                     regex{"(khtml|tasman|links)[\\/\\s]\\(?([\\w\\.]+)", i},                    // KHTML/Tasman/Links
                     regex{"(icab)[\\/\\s]([23]\\.[\\d\\.]+)", i},                               // iCab
                 },
                 {
                     {&Result::engineName},
                     {&Result::engineVersion},
                 }},
                {{
                     regex{"rv\\:([\\w\\.]+).*(gecko)", i}, // Gecko
                 },
                 {
                     {&Result::engineVersion},
                     {&Result::engineName},
                 }},
            },
            {
                // os
                {{
                     // Windows based
                     regex{"microsoft\\s(windows)\\s(vista|xp)", i}, // Windows (iTunes)
                 },
                 {
                     {&Result::osName},
                     {&Result::osVersion},
                 }},
                {{
                     regex{"(windows)\\snt\\s6\\.2;\\s(arm)", i}, // Windows RT
                     regex{"(windows\\sphone(?:\\sos)*|windows\\smobile|windows)[\\s\\/]?([ntce\\d\\.\\s]+\\w)", i},
                 },
                 {
                     {&Result::osName},
                     {&Result::osVersion, FnFixWindowsVersion{}},
                 }},
                {{
                     regex{"(win(?=3|9|n)|win\\s9x\\s)([nt\\d\\.]+)", i},
                 },
                 {
                     {&Result::osName, "Windows"},
                     {&Result::osVersion, FnFixWindowsVersion{}},
                 }},
                {{
                     // Mobile/Embedded OS
                     regex{"\\((bb)(10);", i}, // BlackBerry 10
                 },
                 {
                     {&Result::osName, "BlackBerry"},
                     {&Result::osVersion},
                 }},
                {{
                     regex{"(blackberry)\\w*\\/?([\\w\\.]+)*", i},                                                         // Blackberry
                     regex{"(tizen)[\\/\\s]([\\w\\.]+)", i},                                                               // Tizen
                     regex{"(android|webos|palm\\sos|qnx|bada|rim\\stablet\\sos|meego|contiki)[\\/\\s-]?([\\w\\.]+)*", i}, // Android/WebOS/Palm/QNX/Bada/RIM/MeeGo/Contiki
                     regex{"linux;.+(sailfish);", i},                                                                      // Sailfish OS
                 },
                 {
                     {&Result::osName},
                     {&Result::osVersion},
                 }},
                {{
                     regex{"(symbian\\s?os|symbos|s60(?=;))[\\/\\s-]?([\\w\\.]+)*", i}, // Symbian
                 },
                 {
                     {&Result::osName, "Symbian"},
                     {&Result::osVersion},
                 }},
                {{
                     regex{"\\((series40);", i}, // Series 40
                 },
                 {
                     {&Result::osName},
                 }},
                {{
                     regex{"mozilla.+\\(mobile;.+gecko.+firefox", i}, // Firefox OS
                 },
                 {
                     {&Result::osName, "Firefox OS"},
                     {&Result::osVersion},
                 }},
                {{
                     // Console
                     regex{"(nintendo|playstation)\\s([wids3portablevu]+)", i}, // Nintendo/Playstation
                     // GNU/Linux based
                     regex{"(mint)[\\/\\s\\(]?(\\w+)*", i},                                                                                                                   // Mint
                     regex{"(mageia|vectorlinux)[;\\s]", i},                                                                                                                  // Mageia/VectorLinux
                     regex{"(joli|[kxln]?ubuntu|debian|[open]*suse|gentoo|arch|slackware|fedora|mandriva|centos|pclinuxos|redhat|zenwalk|linpus)[\\/\\s-]?([\\w\\.-]+)*", i}, // Joli/Ubuntu/Debian/SUSE/Gentoo/Arch/Slackware/Fedora/Mandriva/CentOS/PCLinuxOS/RedHat/Zenwalk/Linpus
                     regex{"(hurd|linux)\\s?([\\w\\.]+)*", i},                                                                                                                // Hurd/Linux
                     regex{"(gnu)\\s?([\\w\\.]+)*", i},                                                                                                                       // GNU
                 },
                 {
                     {&Result::osName},
                     {&Result::osVersion},
                 }},
                {{
                     regex{"(cros)\\s[\\w]+\\s([\\w\\.]+\\w)", i}, // Chromium OS
                 },
                 {
                     {&Result::osName, "Chromium OS"},
                     {&Result::osVersion},
                 }},
                {{
                     // Solaris
                     regex{"(sunos)\\s?([\\w\\.]+\\d)*", i}, // Solaris
                 },
                 {
                     {&Result::osName, "Solaris"},
                     {&Result::osVersion},
                 }},
                {{
                     // BSD based
                     regex{"\\s([frentopc-]{0,4}bsd|dragonfly)\\s?([\\w\\.]+)*", i}, // FreeBSD/NetBSD/OpenBSD/PC-BSD/DragonFly
                 },
                 {
                     {&Result::osName},
                     {&Result::osVersion},
                 }},
                {{
                     regex{"(ip[honead]+)(?:.*os\\s*([\\w]+)*\\slike\\smac|;\\sopera)", i}, // iOS
                 },
                 {
                     {&Result::osName, "iOS"},
                     {&Result::osVersion, FnReplace{'_', '.'}},
                 }},
                {{
                     regex{"(mac\\sos\\sx)\\s?([\\w\\s\\.]+\\w)*", i}, // Mac OS
                     regex{"(macintosh|mac(?=_powerpc)\\s)", i},
                 },
                 {
                     {&Result::osName, "Mac OS"},
                     {&Result::osVersion, FnReplace{'_', '.'}},
                 }},
                {{
                     // Other
                     regex{"((?:open)?solaris)[\\/\\s-]?([\\w\\.]+)*", i},                       // Solaris
                     regex{"(haiku)\\s(\\w+)", i},                                               // Haiku
                     regex{"(aix)\\s((\\d)(?=\\.|\\)|\\s)[\\w\\.]*)*", i},                       // AIX
                     regex{"(plan\\s9|minix|beos|os\\/2|amigaos|morphos|risc\\sos|openvms)", i}, // Plan9/Minix/BeOS/OS2/AmigaOS/MorphOS/RISCOS/OpenVMS
                     regex{"(unix)\\s?([\\w\\.]+)*", i},                                         // UNIX
                 },
                 {
                     {&Result::osName},
                     {&Result::osVersion},
                 }},
            },
        };
        return regexes;
    }

private:
    struct FnReplace
    {
        const char old_;
        const char new_;
        std::string operator()(std::string&& s)
        {
            std::replace(s.begin(), s.end(), old_, new_);
            return s;
        }
    };

    struct FnToLower
    {
        std::string operator()(std::string&& s)
        {
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            return s;
        }
    };

    struct FnFixSafariVersion
    {
        std::string operator()(std::string&& s)
        {
            static const auto mapping =
                std::unordered_map<std::string, std::string>{
                    {"/8", "1.0"},
                    {"/1", "1.2"},
                    {"/3", "1.3"},
                    {"/412", "2.0"},
                    {"/416", "2.0.2"},
                    {"/417", "2.0.3"},
                    {"/419", "2.0.4"},
                    {"/", "?"},
                };
            const auto it = mapping.find(s);
            return it != mapping.end() ? it->second : s;
        }
    };

    struct FnFixAmazonDeviceModel
    {
        std::string operator()(std::string&& s)
        {
            static const auto mapping =
                std::unordered_map<std::string, std::string>{
                    {"KF", "Fire Phone"},
                    {"SD", "Fire Phone"},
                };
            const auto it = mapping.find(s);
            return it != mapping.end() ? it->second : s;
        }
    };

    struct FnFixWindowsVersion
    {
        std::string operator()(std::string&& s)
        {
            static const auto mapping =
                std::unordered_map<std::string, std::string>{
                    {"4.90", "ME"},
                    {"NT3.51", "NT 3.11"},
                    {"NT4.0", "NT 4.0"},
                    {"NT 5.0", "2000"},
                    {"NT 5.1", "XP"},
                    {"NT 5.2", "XP"},
                    {"NT 6.0", "Vista"},
                    {"NT 6.1", "7"},
                    {"NT 6.2", "8"},
                    {"NT 6.3", "8.1"},
                    {"NT 6.4", "10"},
                    {"NT 10.0", "10"},
                    {"ARM", "RT"},
                };
            const auto it = mapping.find(s);
            return it != mapping.end() ? it->second : s;
        }
    };

    struct FnFixSprintDeviceModel
    {
        std::string operator()(std::string&& s)
        {
            static const auto mapping =
                std::unordered_map<std::string, std::string>{
                    {"7373KT", "Evo Shift 4G"},
                };
            const auto it = mapping.find(s);
            return it != mapping.end() ? it->second : s;
        }
    };

    struct FnFixSprintDeviceVendor
    {
        std::string operator()(std::string&& s)
        {
            static const auto mapping =
                std::unordered_map<std::string, std::string>{
                    {"APA", "HTC"},
                };
            const auto it = mapping.find(s);
            return it != mapping.end() ? it->second : s;
        }
    };

private:
    struct Extractor
    {
    private:
        using Formatter = std::function<std::string(std::string&&)>;

    private:
        std::string Result::*f_;
        boost::optional<std::string> v_;
        Formatter fn_;

    public:
        Extractor(std::string Result::*f)
        : f_(f)
        , v_()
        , fn_()
        {
        }
        Extractor(std::string Result::*f, std::string v)
        : f_(f)
        , v_(v)
        , fn_()
        {
        }
        Extractor(std::string Result::*f, Formatter fn)
        : f_(f)
        , v_()
        , fn_(std::move(fn))
        {
        }
        void operator()(const std::string& ua,
                        const RegexImpl::smatch& matches,
                        const size_t group,
                        Result& result) const
        {
            if (v_)
            {
                result.*f_ = *v_;
                return;
            }
            if (f_ && matches.size() >= group)
            {
                auto v = matches[group].str();
                result.*f_ = fn_ ? fn_(std::move(v)) : std::move(v);
            }
        }
    };

    struct Matcher
    {
    private:
        std::vector<RegexImpl::regex> expressions_;
        std::vector<Extractor> extractors_;

    public:
        Matcher(std::vector<RegexImpl::regex> expressions,
                std::vector<Extractor> extractors)
        : expressions_(std::move(expressions))
        , extractors_(std::move(extractors))
        {
        }
        bool operator()(const std::string& ua, Result& result) const
        {
            RegexImpl::smatch matches;
            for (const auto& expression : expressions_)
            {
                if (!RegexImpl::regex_search(ua, matches, expression))
                {
                    continue;
                }
                for (size_t idx = 0; idx < extractors_.size(); ++idx)
                {
                    extractors_[idx](ua, matches, idx + 1, result);
                }
                return true;
            }
            return false;
        }
    };
};

} // namespace uap
