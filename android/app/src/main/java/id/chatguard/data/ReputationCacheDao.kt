package id.chatguard.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import id.chatguard.core.model.ReputationResponse

@Entity(tableName = "reputation_cache")
data class ReputationCacheEntity(
    @PrimaryKey
    val sha256: String,
    val verdict: String,
    val threatCategory: String? = null,
    val officialCertMatch: Boolean? = null,
    val flaggedUrls: List<String> = emptyList(),
    val cachedAt: Long = System.currentTimeMillis()
) {
    fun toReputationResponse(): ReputationResponse = ReputationResponse(
        verdict = verdict,
        threatCategory = threatCategory,
        officialCertMatch = officialCertMatch,
        flaggedUrls = flaggedUrls
    )

    companion object {
        fun fromResponse(
            sha256: String,
            response: ReputationResponse,
            cachedAt: Long = System.currentTimeMillis()
        ): ReputationCacheEntity = ReputationCacheEntity(
            sha256 = sha256,
            verdict = response.verdict,
            threatCategory = response.threatCategory,
            officialCertMatch = response.officialCertMatch,
            flaggedUrls = response.flaggedUrls,
            cachedAt = cachedAt
        )
    }
}

@Dao
interface ReputationCacheDao {
    @Query("SELECT * FROM reputation_cache WHERE sha256 = :sha256 LIMIT 1")
    suspend fun get(sha256: String): ReputationCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: ReputationCacheEntity)

    @Query("DELETE FROM reputation_cache WHERE cachedAt < :cutoffTimestamp")
    suspend fun deleteOlderThan(cutoffTimestamp: Long)

    @Query("DELETE FROM reputation_cache")
    suspend fun clear()
}
