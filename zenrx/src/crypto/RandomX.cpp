#include "crypto/RandomX.h"
#include "Log.h"

#include "crypto/randomx/randomx.h"

#include <cpuid.h>

namespace zenrx {

static RandomX s_randomx;

RandomX& randomx()
{
    return s_randomx;
}

RandomX::RandomX()
{
}

RandomX::~RandomX()
{
    release();
}

bool RandomX::hasAES()
{
    uint32_t eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx >> 25) & 1;
}

bool RandomX::hasAVX2()
{
    uint32_t eax, ebx, ecx, edx;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx >> 5) & 1;
}

bool RandomX::init(RxInstanceId id, const std::string& seedHash, int threads,
                   RxAlgo algo, bool hugePages, bool hardwareAES, int initThreads)
{
    std::lock_guard<std::shared_mutex> lock(m_mutex);

    RxInstance* instance = nullptr;

    switch (id) {
    case RxInstanceId::User:
        if (!m_userInstance) {
            m_userInstance = std::make_unique<RxInstance>();
        }
        instance = m_userInstance.get();
        break;

    case RxInstanceId::Dev:
        if (!m_devInstance) {
            m_devInstance = std::make_unique<RxInstance>();
        }
        instance = m_devInstance.get();
        break;
    }

    if (!instance) {
        return false;
    }

    return instance->init(seedHash, threads, algo, hugePages, hardwareAES, initThreads);
}

bool RandomX::init(const std::string& seedHash, int threads,
                   RxAlgo algo, bool hugePages, bool hardwareAES, int initThreads)
{
    return init(RxInstanceId::User, seedHash, threads, algo, hugePages, hardwareAES, initThreads);
}

bool RandomX::reinit(RxInstanceId id, const std::string& seedHash, int threads,
                     bool hardwareAES, int initThreads)
{
    std::lock_guard<std::shared_mutex> lock(m_mutex);

    RxInstance* instance = nullptr;

    switch (id) {
    case RxInstanceId::User:
        instance = m_userInstance.get();
        break;
    case RxInstanceId::Dev:
        instance = m_devInstance.get();
        break;
    }

    if (!instance) {
        return false;
    }

    return instance->reinit(seedHash, threads, hardwareAES, initThreads);
}

bool RandomX::isSeedValid(const std::string& seedHash) const
{
    // Legacy: check user instance
    return isSeedValid(RxInstanceId::User, seedHash);
}

bool RandomX::isSeedValid(RxInstanceId id, const std::string& seedHash) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    const RxInstance* instance = nullptr;

    switch (id) {
    case RxInstanceId::User:
        instance = m_userInstance.get();
        break;
    case RxInstanceId::Dev:
        instance = m_devInstance.get();
        break;
    }

    if (!instance) {
        return false;
    }

    return instance->isValidForSeed(seedHash);
}

randomx_vm* RandomX::getVM(int index)
{
    // Legacy: get from user instance
    return getVM(RxInstanceId::User, index);
}

randomx_vm* RandomX::getVM(RxInstanceId id, int index)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    RxInstance* instance = nullptr;

    switch (id) {
    case RxInstanceId::User:
        instance = m_userInstance.get();
        break;
    case RxInstanceId::Dev:
        instance = m_devInstance.get();
        break;
    }

    if (!instance) {
        return nullptr;
    }

    return instance->getVM(index);
}

RxInstance* RandomX::getInstance(RxInstanceId id)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    switch (id) {
    case RxInstanceId::User:
        return m_userInstance.get();
    case RxInstanceId::Dev:
        return m_devInstance.get();
    }

    return nullptr;
}

void RandomX::release()
{
    std::lock_guard<std::shared_mutex> lock(m_mutex);

    if (m_userInstance) {
        m_userInstance->release();
        m_userInstance.reset();
    }

    if (m_devInstance) {
        m_devInstance->release();
        m_devInstance.reset();
    }
}

void RandomX::release(RxInstanceId id)
{
    std::lock_guard<std::shared_mutex> lock(m_mutex);

    switch (id) {
    case RxInstanceId::User:
        if (m_userInstance) {
            m_userInstance->release();
            m_userInstance.reset();
        }
        break;
    case RxInstanceId::Dev:
        if (m_devInstance) {
            m_devInstance->release();
            m_devInstance.reset();
        }
        break;
    }
}

bool RandomX::allHugePagesEnabled() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    bool userOk = m_userInstance && m_userInstance->isInitialized() && m_userInstance->hasHugePages();
    bool devOk = !m_devInstance || !m_devInstance->isInitialized() || m_devInstance->hasHugePages();

    return userOk && devOk;
}

} // namespace zenrx
