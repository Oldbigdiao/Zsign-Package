#include "bundle.h"
#include "base64.h"
#include "common.h"
#include "macho.h"
#include "sys/stat.h"
#include "sys/types.h"
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace {
enum class PathKind { Missing, Directory, File, Unsafe };

PathKind GetPathKind(const string& path)
{
#ifdef _WIN32
	DWORD attributes = GetFileAttributesA(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES) {
		DWORD error = GetLastError();
		return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) ? PathKind::Missing : PathKind::Unsafe;
	}
	if (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) return PathKind::Unsafe;
	return (attributes & FILE_ATTRIBUTE_DIRECTORY) ? PathKind::Directory : PathKind::File;
#else
	struct stat st = {};
	if (lstat(path.c_str(), &st) != 0) return errno == ENOENT ? PathKind::Missing : PathKind::Unsafe;
	if (S_ISDIR(st.st_mode)) return PathKind::Directory;
	return S_ISREG(st.st_mode) && st.st_nlink == 1 ? PathKind::File : PathKind::Unsafe;
#endif
}

string WithoutTrailingSeparators(const string& path)
{
#ifdef _WIN32
	size_t end = path.find_last_not_of("/\\");
#else
	size_t end = path.find_last_not_of('/');
#endif
	return end == string::npos ? path : path.substr(0, end + 1);
}

bool IsExecutableName(const string& name)
{
	return !name.empty() && name != "." && name != ".." &&
		name.find_first_of("/\\:") == string::npos && name.find('\0') == string::npos;
}

bool ReadSigningPlist(const string& data, jvalue& info)
{
#ifdef __APPLE__
	CFDataRef bytes = CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(data.data()), data.size());
	if (!bytes) return false;
	CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, bytes, kCFPropertyListImmutable, nullptr, nullptr);
	CFRelease(bytes);
	if (!plist) return false;
	bool valid = CFGetTypeID(plist) == CFDictionaryGetTypeID();
	if (valid) {
		CFDictionaryRef dictionary = static_cast<CFDictionaryRef>(plist);
		const pair<const char*, CFStringRef> keys[] = {
			{"CFBundleExecutable", CFSTR("CFBundleExecutable")}, {"CFBundleIdentifier", CFSTR("CFBundleIdentifier")},
			{"CFBundleVersion", CFSTR("CFBundleVersion")}, {"CFBundleDisplayName", CFSTR("CFBundleDisplayName")},
			{"CFBundleName", CFSTR("CFBundleName")}
		};
		for (const auto& [key, lookup] : keys) {
			bool executable = lookup == keys[0].second;
			CFTypeRef value = CFDictionaryGetValue(dictionary, lookup);
			if (!value) continue;
			if (CFGetTypeID(value) != CFStringGetTypeID()) {
				if (executable) valid = false;
				continue;
			}
			CFStringRef str = static_cast<CFStringRef>(value);
			CFRange range = CFRangeMake(0, CFStringGetLength(str));
			CFIndex size = 0;
			CFStringGetBytes(str, range, kCFStringEncodingUTF8, 0, false, nullptr, 0, &size);
			string utf8(size, '\0');
			CFIndex converted = CFStringGetBytes(str, range, kCFStringEncodingUTF8, 0, false,
				reinterpret_cast<UInt8*>(utf8.data()), size, nullptr);
			if (converted != range.length || utf8.find('\0') != string::npos) {
				if (executable) valid = false;
				continue;
			}
			info[key] = utf8;
		}
	}
	CFRelease(plist);
	return valid;
#else
	return info.read_plist(data) && info.is_object();
#endif
}

enum class ExecutableStatus { Missing, Invalid, Valid };
constexpr size_t MaxBundleInfoPlistSize = 1024 * 1024;

ExecutableStatus ReadBundleExecutable(const string& folder, string& data, jvalue& info, string& executable)
{
	if (GetPathKind(folder) != PathKind::Directory) return ExecutableStatus::Invalid;
	string infoPath = folder + "/Info.plist";
	PathKind kind = GetPathKind(infoPath);
	if (kind == PathKind::Missing && ZFile::IsPathSuffix(folder, ".framework")) {
		string resources = folder + "/Resources";
		PathKind resourcesKind = GetPathKind(resources);
		if (resourcesKind != PathKind::Missing && resourcesKind != PathKind::Directory) return ExecutableStatus::Invalid;
		if (resourcesKind == PathKind::Directory) {
			infoPath = resources + "/Info.plist";
			kind = GetPathKind(infoPath);
		}
	}
	if (kind == PathKind::Missing) return ExecutableStatus::Missing;
	if (kind != PathKind::File || !ZFile::ReadFile(infoPath.c_str(), data, MaxBundleInfoPlistSize) ||
		!ReadSigningPlist(data, info)) return ExecutableStatus::Invalid;
	if (!info.has("CFBundleExecutable")) return ExecutableStatus::Missing;
	if (!info["CFBundleExecutable"].is_string()) return ExecutableStatus::Invalid;
	string name = info["CFBundleExecutable"].as_string();
	if (!IsExecutableName(name)) return ExecutableStatus::Invalid;
#ifdef _WIN32
	iconv ic;
	name = ic.U82A(name);
#endif
	executable = folder + "/" + name;
	return GetPathKind(executable) == PathKind::File ? ExecutableStatus::Valid : ExecutableStatus::Invalid;
}
}

ZBundle::ZBundle()
{
	m_pSignAsset = NULL;
	m_bForceSign = false;
	m_bWeakInject = false;
	signFailedFiles = "";
}

bool ZBundle::FindAppFolder(const string& strFolder, string& strAppFolder)
{
	if (GetPathKind(strFolder) != PathKind::Directory) return false;
	if (ZFile::IsPathSuffix(strFolder, ".app") || ZFile::IsPathSuffix(strFolder, ".appex")) {
		strAppFolder = strFolder;
		return true;
	}

	ZFile::EnumFolder(strFolder.c_str(), true, [&](bool bFolder, const string& strPath) {
		string strName = ZUtil::GetBaseName(strPath.c_str());
		if ("__MACOSX" == strName || (bFolder && GetPathKind(strPath) != PathKind::Directory)) {
			return true;
		}
		return false;
	}, [&](bool bFolder, const string& strPath) {
		if (bFolder) {
			if (ZFile::IsPathSuffix(strPath, ".app") || ZFile::IsPathSuffix(strPath, ".appex")) {
				strAppFolder = strPath;
				return true;
			}
		}
		return false;
	});

	return (!strAppFolder.empty());
}

string ZBundle::BundleExecutable(const string& path)
{
	string data, executable;
	jvalue info;
	return ReadBundleExecutable(WithoutTrailingSeparators(path), data, info, executable) == ExecutableStatus::Valid ? executable : "";
}

bool ZBundle::ValidateBundle(const string& path)
{
	ZBundle bundle;
	bundle.m_strAppFolder = WithoutTrailingSeparators(path);
	jvalue root;
	root["path"] = "/";
	return bundle.GetSignFolderInfo(bundle.m_strAppFolder, root, true) && bundle.GetObjectsToSign(bundle.m_strAppFolder, root);
}

bool ZBundle::GetSignFolderInfo(const string& strFolder, jvalue& jvNode, bool bRoot)
{
	string strInfoPlistData, strExePath;
	jvalue jvInfo;
	ExecutableStatus status = ReadBundleExecutable(strFolder, strInfoPlistData, jvInfo, strExePath);
	if (!bRoot && status == ExecutableStatus::Missing) return true;
	string strBundleId = jvInfo["CFBundleIdentifier"];
	string strBundleVersion = jvInfo["CFBundleVersion"];
	if (status != ExecutableStatus::Valid || strBundleId.empty()) {
		ZLog::ErrorV(">>> Invalid bundle executable or Info.plist: %s\n", strFolder.c_str());
		return false;
	}

	string strInfoSHA1;
	string strInfoSHA256;
	ZSHA::SHABase64(strInfoPlistData, strInfoSHA1, strInfoSHA256);

	jvNode["bundle_id"] = strBundleId;
	jvNode["bundle_version"] = strBundleVersion;
	jvNode["bundle_executable"] = jvInfo["CFBundleExecutable"];
	jvNode["sha1"] = strInfoSHA1;
	jvNode["sha256"] = strInfoSHA256;
	if (!jvNode.has("path")) {
		jvNode["path"] = strFolder.substr(m_strAppFolder.size() + 1);
	}

	if (bRoot) {
		string strBundleName = jvInfo["CFBundleDisplayName"];
		if (strBundleName.empty()) {
			strBundleName = jvInfo["CFBundleName"].as_cstr();
		}
		jvNode["name"] = strBundleName;
	}

	return true;
}

bool ZBundle::GetObjectsToSign(const string& strFolder, jvalue& jvInfo)
{
	bool valid = true;
	bool enumerated = ZFile::EnumFolder(strFolder.c_str(), false, nullptr, [&](bool, const string& path) {
		PathKind kind = GetPathKind(path);
		if (kind == PathKind::Directory) {
			// 子包必须在父包之前签名，父包的 CodeResources 才能覆盖其最终内容。
			valid = GetObjectsToSign(path, jvInfo);
			if (valid && (ZFile::IsPathSuffix(path, ".app") || ZFile::IsPathSuffix(path, ".appex") ||
				ZFile::IsPathSuffix(path, ".framework") || ZFile::IsPathSuffix(path, ".xctest"))) {
				jvalue node;
				valid = GetSignFolderInfo(path, node);
				if (valid && node.has("bundle_executable")) jvInfo["folders"].push_back(node);
			}
		} else if (kind == PathKind::File) {
			if (ZFile::IsPathSuffix(path, ".dylib")) jvInfo["files"].push_back(path.substr(m_strAppFolder.size() + 1));
		} else {
			ZLog::ErrorV(">>> Unsafe bundle entry: %s\n", path.c_str());
			valid = false;
		}
		return !valid;
	});
	return enumerated && valid;
}

bool ZBundle::GenerateCodeResources(const string& strFolder, const string& strBundleExe, jvalue& jvCodeRes)
{
	set<string> setFiles;
	ZFile::EnumFolder(strFolder.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
		if (!bFolder) {
			string strNode = strPath.substr(strFolder.size() + 1);
			ZUtil::StringReplace(strNode, "\\", "/");
			setFiles.insert(strNode);
		}
		return false;
	});

#ifdef _WIN32
	iconv ic;
#endif

	setFiles.erase("_CodeSignature/CodeResources");
	setFiles.erase(strBundleExe);
	
	jvCodeRes.clear();
	jvCodeRes["files"] = jvalue(jvalue::E_OBJECT);
	jvCodeRes["files2"] = jvalue(jvalue::E_OBJECT);

	for (string strKey : setFiles) {
		string strFile = strFolder + "/" + strKey;
		string strSHA1Base64;
		string strSHA256Base64;
		ZSHA::SHABase64File(strFile.c_str(), strSHA1Base64, strSHA256Base64);

#ifdef _WIN32
		strKey = ic.A2U8(strKey);
#endif

		bool bomit1 = false;
		bool bomit2 = false;

		if (ZFile::IsPathSuffix(strKey, ".lproj/locversion.plist")) {
			bomit1 = true;
			bomit2 = true;
		}

		if (ZFile::IsPathSuffix(strKey, ".DS_Store") || "Info.plist" == strKey || "PkgInfo" == strKey) {
			bomit2 = true;
		}

		if (!bomit1) {
			if (string::npos != strKey.rfind(".lproj/")) {
				jvCodeRes["files"][strKey]["hash"] = "data:" + strSHA1Base64;
				jvCodeRes["files"][strKey]["optional"] = true;
			} else {
				jvCodeRes["files"][strKey] = "data:" + strSHA1Base64;
			}
		}

		if (!bomit2) {
			jvCodeRes["files2"][strKey]["hash"] = "data:" + strSHA1Base64;
			jvCodeRes["files2"][strKey]["hash2"] = "data:" + strSHA256Base64;
			if (string::npos != strKey.rfind(".lproj/")) {
				jvCodeRes["files2"][strKey]["optional"] = true;
			}
		}
	}

	jvCodeRes["rules"]["^.*"] = true;
	jvCodeRes["rules"]["^.*\\.lproj/"]["optional"] = true;
	jvCodeRes["rules"]["^.*\\.lproj/"]["weight"] = 1000.0;
	jvCodeRes["rules"]["^.*\\.lproj/locversion.plist$"]["omit"] = true;
	jvCodeRes["rules"]["^.*\\.lproj/locversion.plist$"]["weight"] = 1100.0;
	jvCodeRes["rules"]["^Base\\.lproj/"]["weight"] = 1010.0;
	jvCodeRes["rules"]["^version.plist$"] = true;

	jvCodeRes["rules2"]["^.*"] = true;
	jvCodeRes["rules2"][".*\\.dSYM($|/)"]["weight"] = 11.0;
	jvCodeRes["rules2"]["^(.*/)?\\.DS_Store$"]["omit"] = true;
	jvCodeRes["rules2"]["^(.*/)?\\.DS_Store$"]["weight"] = 2000.0;
	jvCodeRes["rules2"]["^.*\\.lproj/"]["optional"] = true;
	jvCodeRes["rules2"]["^.*\\.lproj/"]["weight"] = 1000.0;
	jvCodeRes["rules2"]["^.*\\.lproj/locversion.plist$"]["omit"] = true;
	jvCodeRes["rules2"]["^.*\\.lproj/locversion.plist$"]["weight"] = 1100.0;
	jvCodeRes["rules2"]["^Base\\.lproj/"]["weight"] = 1010.0;
	jvCodeRes["rules2"]["^Info\\.plist$"]["omit"] = true;
	jvCodeRes["rules2"]["^Info\\.plist$"]["weight"] = 20.0;
	jvCodeRes["rules2"]["^PkgInfo$"]["omit"] = true;
	jvCodeRes["rules2"]["^PkgInfo$"]["weight"] = 20.0;
	jvCodeRes["rules2"]["^embedded\\.provisionprofile$"]["weight"] = 20.0;
	jvCodeRes["rules2"]["^version\\.plist$"]["weight"] = 20.0;

	return true;
}

void ZBundle::GetChangedFiles(jvalue& jvNode, vector<string>& arrChangedFiles)
{
	if (jvNode.has("files")) {
		for (size_t i = 0; i < jvNode["files"].size(); i++) {
			arrChangedFiles.push_back(jvNode["files"][i]);
		}
	}

	if (jvNode.has("folders")) {
		for (size_t i = 0; i < jvNode["folders"].size(); i++) {
			jvalue& jvSubNode = jvNode["folders"][i];
			GetChangedFiles(jvSubNode, arrChangedFiles);
			string strPath = jvSubNode["path"];
			arrChangedFiles.push_back(strPath + "/_CodeSignature/CodeResources");
			arrChangedFiles.push_back(strPath + "/" + jvSubNode["bundle_executable"].as_string());
		}
	}
}

void ZBundle::GetNodeChangedFiles(jvalue& jvNode, bool excludeProvisioning)
{
	if (jvNode.has("folders")) {
		for (size_t i = 0; i < jvNode["folders"].size(); i++) {
			GetNodeChangedFiles(jvNode["folders"][i], excludeProvisioning);
		}
	}

	vector<string> arrChangedFiles;
	GetChangedFiles(jvNode, arrChangedFiles);
	for (size_t i = 0; i < arrChangedFiles.size(); i++) {
		jvNode["changed"].push_back(arrChangedFiles[i]);
	}
	
	if (excludeProvisioning) {
		if ("/" == jvNode["path"]) { // root
			jvNode["changed"].push_back("embedded.mobileprovision");
		}
	}
}

bool ZBundle::SignNode(jvalue& jvNode)
{
	if (jvNode.has("files")) {
		for (size_t i = 0; i < jvNode["files"].size(); i++) {
			string strFile = jvNode["files"][i];
			ZLog::PrintV(">>> SignFile: \t%s\n", strFile.c_str());
			ZMachO macho;
			if (macho.InitV("%s/%s", m_strAppFolder.c_str(), strFile.c_str())) {
				if (!macho.Sign(m_pSignAsset, m_bForceSign, "", "", "", "")) {
					signFailedFiles += strFile;
					signFailedFiles += "\n";
				}
			}
		}
	}
	
	if (jvNode.has("folders")) {
		for (size_t i = 0; i < jvNode["folders"].size(); i++) {
			if (!SignNode(jvNode["folders"][i])) {
				return false;
			}
		}
	}

	jbase64 b64;
	string strInfoSHA1;
	string strInfoSHA256;
	string strFolder = jvNode["path"];
	string strBundleId = jvNode["bundle_id"];
	string strBundleExe = jvNode["bundle_executable"];
	b64.decode(jvNode["sha1"].as_cstr(), strInfoSHA1);
	b64.decode(jvNode["sha256"].as_cstr(), strInfoSHA256);
	if (strBundleId.empty() || strBundleExe.empty() || strInfoSHA1.empty() ||
		strInfoSHA256.empty()) {
		ZLog::ErrorV(">>> Can't get BundleID or BundleExecute or Info.plist SHASum in Info.plist! %s\n", strFolder.c_str());
		return false;
	}

#ifdef _WIN32
	iconv ic;
	strBundleExe = ic.U82A(strBundleExe);
#endif

	string strBaseFolder = m_strAppFolder;
	if ("/" != strFolder) {
		strBaseFolder += "/";
		strBaseFolder += strFolder;
	}

	string strExePath = strBaseFolder + "/" + strBundleExe;
	if (!IsExecutableName(strBundleExe) || GetPathKind(strExePath) != PathKind::File) {
		ZLog::ErrorV(">>> Invalid bundle executable: %s\n", strBaseFolder.c_str());
		return false;
	}
	ZLog::PrintV(">>> SignFolder: %s, (%s)\n", ("/" == strFolder) ? ZUtil::GetBaseName(m_strAppFolder.c_str()) : strFolder.c_str(), strBundleExe.c_str());

	ZMachO macho;
	if (!macho.Init(strExePath.c_str())) {
		ZLog::ErrorV(">>> Can't parse BundleExecute file! %s\n", strExePath.c_str());
		signFailedFiles += strExePath;
		signFailedFiles += "\n";
		return true;
	}

	ZFile::CreateFolderV("%s/_CodeSignature", strBaseFolder.c_str());
	string strCodeResFile = strBaseFolder + "/_CodeSignature/CodeResources";

	jvalue jvCodeRes;
	if (!m_bForceSign) {
		jvCodeRes.read_plist_from_file(strCodeResFile.c_str());
	}

	if (m_bForceSign || jvCodeRes.is_null()) { // create
		if (!GenerateCodeResources(strBaseFolder, strBundleExe, jvCodeRes)) {
			ZLog::ErrorV(">>> Create CodeResources failed! %s\n", strBaseFolder.c_str());
			return false;
		}
	} else if (jvNode.has("changed")) { // use existsed
		for (size_t i = 0; i < jvNode["changed"].size(); i++) {
			string strFile = jvNode["changed"][i].as_cstr();
			string strRealFile = m_strAppFolder + "/" + strFile;

			string strFileSHA1;
			string strFileSHA256;
			if (!ZSHA::SHABase64File(strRealFile.c_str(), strFileSHA1, strFileSHA256)) {
				ZLog::ErrorV(">>> Can't get changed file SHASum! %s", strFile.c_str());
				return false;
			}

			string strKey = strFile;
			if ("/" != strFolder) {
				strKey = strFile.substr(strFolder.size() + 1);
			}

			jvCodeRes["files"][strKey] = "data:" + strFileSHA1;
			jvCodeRes["files2"][strKey]["hash"] = "data:" + strFileSHA1;
			jvCodeRes["files2"][strKey]["hash2"] = "data:" + strFileSHA256;

			ZLog::DebugV("\t\tChanged file: %s, %s\n", strFileSHA1.c_str(), strKey.c_str());
		}
	}

	string strCodeResData;
	jvCodeRes.style_write_plist(strCodeResData);
	if (!ZFile::WriteFile(strCodeResFile.c_str(), strCodeResData)) {
		ZLog::ErrorV("\tWriting CodeResources failed! %s\n", strCodeResFile.c_str());
		return false;
	}

	bool bForceSign = m_bForceSign;
	if ("/" == strFolder) { // inject dylib
		for (const string& strDylibFile : m_arrInjectDylibs) {
			if (macho.InjectDylib(m_bWeakInject, strDylibFile.c_str())) {
				bForceSign = true;
			}
		}
	}

	if (!macho.Sign(m_pSignAsset, bForceSign, strBundleId, strInfoSHA1, strInfoSHA256, strCodeResData)) {
		return false;
	}

	return true;
}

bool ZBundle::ModifyPluginsBundleId(const string& strOldBundleId, const string& strNewBundleId)
{
	vector<string> arrFolders;
	ZFile::EnumFolder(m_strAppFolder.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
		if (bFolder) {
			if (ZFile::IsPathSuffix(strPath, ".app") || ZFile::IsPathSuffix(strPath, ".appex")) {
				arrFolders.push_back(strPath);
			}
		}
		return false;
	});

	for (const string& strFolder: arrFolders) {
		jvalue jvInfo;
		if (!jvInfo.read_plist_from_file("%s/Info.plist", strFolder.c_str())) {
			ZLog::WarnV(">>> Can't find Plugin's Info.plist! %s\n", strFolder.c_str());
			continue;
		}

		string strOldPIBundleID = jvInfo["CFBundleIdentifier"];
		string strNewPIBundleID = strOldPIBundleID;
		ZUtil::StringReplace(strNewPIBundleID, strOldBundleId, strNewBundleId);
		jvInfo["CFBundleIdentifier"] = strNewPIBundleID;
		ZLog::PrintV(">>> BundleId: \t%s -> %s, Plugin\n", strOldPIBundleID.c_str(), strNewPIBundleID.c_str());

		if (jvInfo.has("WKCompanionAppBundleIdentifier")) {
			string strOldWKCBundleID = jvInfo["WKCompanionAppBundleIdentifier"];
			string strNewWKCBundleID = strOldWKCBundleID;
			ZUtil::StringReplace(strNewWKCBundleID, strOldBundleId, strNewBundleId);
			jvInfo["WKCompanionAppBundleIdentifier"] = strNewWKCBundleID;
			ZLog::PrintV(">>> BundleId: \t%s -> %s, Plugin-WKCompanionAppBundleIdentifier\n", strOldWKCBundleID.c_str(), strNewWKCBundleID.c_str());
		}

		if (jvInfo.has("NSExtension")) {
			if (jvInfo["NSExtension"].has("NSExtensionAttributes")) {
				if (jvInfo["NSExtension"]["NSExtensionAttributes"].has("WKAppBundleIdentifier")) {
					string strOldWKBundleID = jvInfo["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"];
					string strNewWKBundleID = strOldWKBundleID;
					ZUtil::StringReplace(strNewWKBundleID, strOldBundleId, strNewBundleId);
					jvInfo["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"] = strNewWKBundleID;
					ZLog::PrintV(">>> BundleId: \t%s -> %s, NSExtension-NSExtensionAttributes-WKAppBundleIdentifier\n", strOldWKBundleID.c_str(), strNewWKBundleID.c_str());
				}
			}
		}

		jvInfo.style_write_plist_to_file("%s/Info.plist", strFolder.c_str());
	}

	return true;
}

bool ZBundle::ModifyBundleInfo(const string& strBundleId, const string& strBundleVersion, const string& strDisplayName)
{
	jvalue jvInfo;
	if (!jvInfo.read_plist_from_file("%s/Info.plist", m_strAppFolder.c_str())) {
		ZLog::ErrorV(">>> Can't find app's Info.plist! %s\n", m_strAppFolder.c_str());
		return false;
	}

	if (!strBundleId.empty()) {
		string strOldBundleId = jvInfo["CFBundleIdentifier"];
		jvInfo["CFBundleIdentifier"] = strBundleId;
		ZLog::PrintV(">>> BundleId: \t%s -> %s\n", strOldBundleId.c_str(), strBundleId.c_str());
		ModifyPluginsBundleId(strOldBundleId, strBundleId);
	}

	if (!strDisplayName.empty()) {

		string strNewDisplayName = strDisplayName;

#ifdef _WIN32
		iconv ic;
		strNewDisplayName = ic.A2U8(strDisplayName);
#endif

		string strOldDisplayName = jvInfo["CFBundleDisplayName"];
		if (strOldDisplayName.empty()) {
			strOldDisplayName = jvInfo["CFBundleName"].as_cstr();
		}

		jvInfo["CFBundleName"] = strNewDisplayName;
		jvInfo["CFBundleDisplayName"] = strNewDisplayName;

		jvalue jvInfoStrings;
		if (jvInfoStrings.read_plist_from_file("%s/zh_CN.lproj/InfoPlist.strings", m_strAppFolder.c_str())) {
			jvInfoStrings["CFBundleName"] = strNewDisplayName;
			jvInfoStrings["CFBundleDisplayName"] = strNewDisplayName;
			jvInfoStrings.style_write_plist_to_file("%s/zh_CN.lproj/InfoPlist.strings", m_strAppFolder.c_str());
		}

		jvInfoStrings.clear();
		if (jvInfoStrings.read_plist_from_file("%s/zh-Hans.lproj/InfoPlist.strings", m_strAppFolder.c_str())) {
			jvInfoStrings["CFBundleName"] = strNewDisplayName;
			jvInfoStrings["CFBundleDisplayName"] = strNewDisplayName;
			jvInfoStrings.style_write_plist_to_file("%s/zh-Hans.lproj/InfoPlist.strings", m_strAppFolder.c_str());
		}

#ifdef _WIN32
		strOldDisplayName = ic.U82A(strOldDisplayName);
		strNewDisplayName = ic.U82A(strNewDisplayName);
#endif

		ZLog::PrintV(">>> BundleName: %s -> %s\n", strOldDisplayName.c_str(), strNewDisplayName.c_str());
	}

	if (!strBundleVersion.empty()) {
		string strOldBundleVersion = jvInfo["CFBundleVersion"];
		jvInfo["CFBundleVersion"] = strBundleVersion;
		jvInfo["CFBundleShortVersionString"] = strBundleVersion;
		ZLog::PrintV(">>> BundleVersion: %s -> %s\n", strOldBundleVersion.c_str(), strBundleVersion.c_str());
	}

	jvInfo.style_write_plist_to_file("%s/Info.plist", m_strAppFolder.c_str());
	return true;
}

bool ZBundle::SignFolder(ZSignAsset* pSignAsset,
							const string& strFolder,
							const string& strBundleId,
							const string& strBundleVersion,
							const string& strDisplayName,
							const vector<string>& arrInjectDylibs,
							bool bForce,
							bool bWeakInject,
							bool bEnableCache,
							bool excludeProvisioning)
{
	m_bForceSign = bForce;
	m_pSignAsset = pSignAsset;
	m_bWeakInject = bWeakInject;
	if (NULL == m_pSignAsset) {
		return false;
	}

	m_strAppFolder.clear();
	if (!FindAppFolder(WithoutTrailingSeparators(strFolder), m_strAppFolder)) {
		ZLog::ErrorV(">>> Can't find app folder! %s\n", strFolder.c_str());
		return false;
	}

	// 每次从当前目录生成签名清单，旧缓存只决定是否复用签名，不能提供路径。
	jvalue jvRoot;
	auto readSigningTree = [&]() {
		jvRoot.clear();
		jvRoot["path"] = "/";
		jvRoot["root"] = m_strAppFolder;
		return GetSignFolderInfo(m_strAppFolder, jvRoot, true) && GetObjectsToSign(m_strAppFolder, jvRoot);
	};
	if (!readSigningTree()) return false;

	if (!strBundleId.empty() || !strDisplayName.empty() || !strBundleVersion.empty()) {
		m_bForceSign = true;
		if (!ModifyBundleInfo(strBundleId, strBundleVersion, strDisplayName)) {
			return false;
		}
	}

	ZFile::RemoveFileV("%s/embedded.mobileprovision", m_strAppFolder.c_str());
	if (!pSignAsset->m_strProvData.empty()) {
		if (excludeProvisioning) {
			if (!ZFile::WriteFileV(pSignAsset->m_strProvData, "%s/embedded.mobileprovision", m_strAppFolder.c_str())) { // embedded.mobileprovision
				ZLog::ErrorV(">>> Can't write embedded.mobileprovision!\n");
				return false;
			}
		}
	}

	if (!arrInjectDylibs.empty()) {
		m_bForceSign = true;
		for (const string& strDylibFile : arrInjectDylibs) {
			string strFileName = ZUtil::GetBaseName(strDylibFile.c_str());
			if (ZFile::CopyFileV(strDylibFile.c_str(), "%s/%s", m_strAppFolder.c_str(), strFileName.c_str())) {
				m_arrInjectDylibs.push_back("@executable_path/" + strFileName);
			}
		}
	}

	string strCacheName;
	ZSHA::SHA1Text(m_strAppFolder, strCacheName);
	if (!ZFile::IsFileExistsV("./.zsign_cache/%s.json", strCacheName.c_str())) {
		m_bForceSign = true;
	}

	if ((!strBundleId.empty() || !strDisplayName.empty() || !strBundleVersion.empty() || !arrInjectDylibs.empty()) &&
		!readSigningTree()) return false;
	GetNodeChangedFiles(jvRoot, excludeProvisioning);

	string strAppName = jvRoot["name"];

#ifdef _WIN32
	iconv ic;
	strAppName = ic.U82A(strAppName);
#endif

	ZLog::PrintV(">>> Signing: \t%s ...\n", m_strAppFolder.c_str());
	ZLog::PrintV(">>> AppName: \t%s\n", strAppName.c_str());
	ZLog::PrintV(">>> BundleId: \t%s\n", jvRoot["bundle_id"].as_cstr());
	ZLog::PrintV(">>> Version: \t%s\n", jvRoot["bundle_version"].as_cstr());
	ZLog::PrintV(">>> TeamId: \t%s\n", m_pSignAsset->m_strTeamId.c_str());
	ZLog::PrintV(">>> SubjectCN: \t%s\n", m_pSignAsset->m_strSubjectCN.c_str());
	ZLog::PrintV(">>> ReadCache: \t%s\n", m_bForceSign ? "NO" : "YES");
	ZLog::PrintV(">>> Exclude MobileProvision: \t%s\n", excludeProvisioning ? "NO" : "YES");

	if (SignNode(jvRoot)) {
		if (bEnableCache) {
			ZFile::CreateFolder("./.zsign_cache");
			jvRoot.style_write_to_file("./.zsign_cache/%s.json", strCacheName.c_str());
		}
		return true;
	}

	return false;
}
