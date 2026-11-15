package id.chatguard.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class ChatGuardTypeConverters {
    private val json = Json { ignoreUnknownKeys = true }

    @TypeConverter
    fun fromStringList(value: List<String>?): String {
        return value?.let { json.encodeToString(it) } ?: "[]"
    }

    @TypeConverter
    fun toStringList(value: String?): List<String> {
        if (value.isNullOrBlank()) return emptyList()
        return try {
            json.decodeFromString<List<String>>(value)
        } catch (_: Exception) {
            emptyList()
        }
    }
}

@Database(entities = [ReputationCacheEntity::class], version = 1, exportSchema = false)
@TypeConverters(ChatGuardTypeConverters::class)
abstract class ChatGuardDatabase : RoomDatabase() {
    abstract fun reputationCacheDao(): ReputationCacheDao

    companion object {
        @Volatile
        private var INSTANCE: ChatGuardDatabase? = null

        fun getInstance(context: Context): ChatGuardDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    ChatGuardDatabase::class.java,
                    "chatguard.db"
                ).build().also { INSTANCE = it }
            }
        }
    }
}
