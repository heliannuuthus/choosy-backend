-- Zwei 模块初始化数据
-- 注意：此文件会在 schema.sql 之后执行，此时 zwei 数据库已存在并已选中
-- 从 01-init.sql 迁移，已修复 INSERT 语句格式（移除 _id，使用 AUTO_INCREMENT）

-- 使用 zwei 数据库
USE `zwei`;

-- Choosy 数据库初始化数据
-- MySQL 语法
-- 从 SQLite 数据库迁移

-- ==================== t_additional_note ====================

INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '选择新鲜的螃蟹是关键，肉质会更加鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '咖喱块的选择也很重要，推荐使用带有蟹黄风味的咖喱块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '在煎螃蟹时，一定要小心，避免蟹黄流出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '焖煮过程中，保持中小火，让咖喱味充分渗入螃蟹。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '关火后继续翻炒，防止蛋清凝固成块，使酱汁更加顺滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '鳝鱼可以让摊主帮忙宰杀，保留一些血水可以避免发黑发臭。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '多加一些胡椒粉和白糖有利于去腥增香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '勾芡时要边倒边快速翻炒，防止结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '热油浇在蒜末和葱花上会发出“滋滋”声，香气四溢。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '鱼片厚度会影响微波时间，建议每片鱼肉厚度约为1.5-2厘米。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '如果微波炉功率不同，请适当调整微波时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '可以在微波前将葱姜与料酒均匀涂抹在鱼片的两侧，以增加香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '热油淋上去时要小心，避免烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '巴沙鱼切片时可以垂直于鱼片长条的方向先剁成5cm的鱼块，然后翻转90度斜着撇成薄片。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '腌制鱼片时不要用力过猛，以免鱼片碎裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '蔬菜可以根据个人喜好自由搭配，但需要注意各种蔬菜的特点，比如土豆需要煮熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '红油豆瓣酱和盐的用量可根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '选购生蚝时，应选择壳紧闭、无异味的新鲜生蚝。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '蒸制时间不宜过长，以免肉质变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '可以根据个人口味添加适量的辣椒油或其他调料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '处理生蚝时要注意卫生，避免交叉污染。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '煎鱼前一定要将鱼身擦干水分，避免溅油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '炖煮过程中可以适当翻动鱼身，使其均匀受热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '调味品的用量可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '收汁时注意观察，避免烧焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '处理鱼头时要小心，可以戴手套防止划伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '腌制时间不宜过长，以免鱼肉变质。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '调味料可以根据个人口味适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '大火收汁时要注意观察，避免烧干。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '炸鱼时不要频繁翻动，以免鱼肉散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '五花肉的油脂可以使鱼肉更加香醇。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '焖煮时一定要加盖，以保持鱼肉的鲜嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '收汁时要不断翻动鱼身，使汤汁均匀地裹在鱼身上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '不与柿子、浓茶同食', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '痛风患者慎食', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '被蟹夹或烫伤：立即冷水冲15分钟；伤口深或严重者务必就医', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '本菜谱欢迎反馈优化建议（Issue/Pull Request）', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '螃蟹一定要新鲜，选择活蟹最佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '处理螃蟹时要注意卫生，去除不可食用的部分。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '炒酱料时火候不宜过大，以免炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '蒸制时间根据螃蟹大小适当调整，确保熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '炖煮酱汁时可以适当加一些料酒，增加香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '可以选择不同口味的果酱，增加早餐的多样性。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '如果喜欢更丰富的口感，可以在果酱中加入一些坚果碎或水果丁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '使用面包机烘烤吐司时，可以根据个人喜好调整烘烤时间，以达到理想的酥脆程度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '用餐巾纸包裹吐司可以方便携带，但建议尽快食用以保持最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '可以根据个人口味调整盐的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '使用新鲜的鸡蛋可以使成品更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '微波炉加热时间可能因型号不同而有所差异，请根据实际情况调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '确保鸡蛋是新鲜的，这样煮出来的蛋更美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '使用温度计精确控制水温，确保烹饪效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '如果觉得32分钟的操作过于复杂，可以尝试传统的煮蛋方法，同样可以获得不错的口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '冰水的作用是迅速降低蛋的温度，防止余热继续加热蛋黄，使其更加嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '如果想进一步避免蛋黄和蛋白溅射，可以在碗上盖一个微波炉适用的盖子。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '不同微波炉的功率可能有所不同，建议初次尝试时观察蛋液状态，适当调整加热时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '可以根据个人口味添加其他调料，如胡椒粉或葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '蛋液与水比例控制在1:1至1:1.2之间口感最佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '覆盖保鲜膜并扎孔能防止表面爆开或出现蜂窝。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '过筛可显著提升细腻度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '若表面鼓泡或出水，说明加热过头，下次缩短时间即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '确保所有食材都在室温下使用，这样更容易混合均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '如果喜欢更湿润的口感，可以在面糊中加入少量牛奶。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '微波炉功率不同，加热时间可能需要适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '可以尝试不同的口味组合，创造属于自己的独特风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '使用开水与冷水混合和面，有助于提升饼皮柔韧度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '剩余生饼皮可冷藏保存24小时，使用时回温擀平即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '煎饼时可以适当调整火候，以达到理想的色泽和口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '对粥的稀稠程度有不同喜好的朋友可以酌情增加或减少水的用量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '煮出来的粥是甜的，可以通过控制加入桂圆的数量控制甜度', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '如果喜欢更丰富的口感，可以在粥快煮好时加入适量的枸杞或其他坚果', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '选择新鲜的玉米是关键，新鲜的玉米口感更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '煮玉米时，可以根据个人喜好调整盐和糖的比例。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '煮玉米的时间不宜过长，否则玉米会变得太软，失去原有的口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', '选择新鲜的鸡蛋，蛋黄更饱满且不易散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', '冷水冲洗不仅可以止熟，还能帮助剥壳，防止蛋壳粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', '如果担心沙门氏菌感染，建议使用经过巴氏杀菌处理的鸡蛋或延长煮制时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '操作时需时刻观察锅内情况，切记不可分神玩手机。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '如果饺子较多，可以分批煎制，避免拥挤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '可以根据个人口味添加其他调料，如辣椒油、醋等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '可以根据个人口味添加其他配料，如奶酪丝、火腿丁等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '煎饼时使用小火，避免燕麦部分煎糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '剩余的牛奶可以作为饮品搭配食用，增加饱腹感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '如果使用快煮燕麦，可以直接将燕麦和牛奶混合后放入微波炉中，中等火力微波4分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '不建议混合物超过容器容量的50%，否则加热过程中内容物极有可能溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '不建议使用玻璃杯进行烹饪，理由同上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '搭配水果蔬菜和苏打饼干食用更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '根据个人口味，可以在燕麦中加入蜂蜜或果干增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', '选择全麦或粗粮面包片，营养价值更高，更有利于减脂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', '可以根据个人口味，在面包片上撒一些肉桂粉或蜂蜜，增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', '如果喜欢更酥脆的口感，可以在烘烤过程中多翻面几次。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '如果喜欢更丰富的口感，可以在最后一步加入炒好的番茄丁、洋葱丁、培根丁或切好的芝士小丁等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '使用口径较小的不粘锅更容易在锅中均匀搅拌，适合一人食。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '可以根据个人口味调整盐的用量，也可以加入少许黑胡椒粉增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '如果没有上述香料，可以使用现成的卤料包代替。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '根据个人口味调整食盐的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '煮好的茶叶蛋可以放在冰箱中保存，食用前加热即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '蛋液与水的比例一般为1:1.5，可以根据个人喜好调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '蒸制过程中保持中小火，避免水沸腾过猛导致蛋液表面不平整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '出锅后可以根据个人口味加入蒸鱼豉油、葱花和香油作为佐料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '发酵过程中，可以在锅里加一些热水，提高发酵环境的温度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '如果想让花卷更有风味，可以在面团中加入葱花、芝麻等调料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '蒸制前确保锅中的水足够多，避免干烧。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '如果糍粑是冷冻的，需要提前解冻至室温再进行切割和煎制。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '煎制过程中要保持小火，以免外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '可以根据个人喜好撒上适量的红糖，增加甜味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '煎好的糍粑应外皮酥脆，内部软糯，色泽金黄。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '金枪鱼酱可以在前一天晚上做好并放入冰箱冷藏，第二天早上直接使用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '金枪鱼酱建议冷藏时间不超过一周，需要使用保鲜膜盖住。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '如果没有轻食机，可以使用平底锅或烤箱代替，同样可以做出美味的三明治。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '可以在鸡蛋酱中加入一些切碎的酸黄瓜或芝士片增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '如果喜欢更丰富的口感，可以在煎培根的同时煎一片奶酪，夹在三明治中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '油酥的稠度可以根据个人喜好调整，喜欢稀一些的可以适当增加油量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '制作好的油酥可以冷藏保存，但最好在一周内使用完毕。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '油酥不仅可以用于烙饼，还可以用来制作各种中式点心，如葱油饼、酥皮等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '可以根据个人口味调整各种调料的比例。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '热油时要小心，避免烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '制作好的酱料可以放在密封容器中冷藏保存，随用随取。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '如果喜欢更浓郁的香气，可以在最后一步加入适量的蒜末或葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '炒糖色过程中火候控制非常关键，过大会导致糖色发苦，过小则糖色不够红亮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '糖色完成后应迅速进行下一步操作，否则容易发苦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '可以提前准备好所有材料和工具，以便快速操作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '如果喜欢更浓稠的糖醋汁，可以在最后一步加入适量水淀粉勾芡。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '糖醋汁的比例可以根据个人口味进行微调，例如喜欢更甜一些可以增加白糖的量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '糖醋汁做好后，最好立即使用以保持最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '炸葱油时，火候要控制好，中小火慢炸，避免焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '葱油可以保存在干净的玻璃瓶中，密封冷藏，保质期较长。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '炸过的料渣也可以食用，可以用作调味料或拌饭。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '根据个人口味，可以在炸油过程中加入其他香料如八角、桂皮等，增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '蒜头切末时尽量保持大小一致，这样炸出来的蒜末颜色和口感更均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '如果喜欢更香浓的味道，可以在最后一步加入少许葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '蒜香酱油最好现做现吃，若需保存，请放入冰箱冷藏，保质期约为一周。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '确保所有工具和杯子都干净无水渍，以免影响分层效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '点火前请确保周围没有易燃物品，并且操作者熟悉安全措施。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '饮用时请注意适量，这款鸡尾酒酒精含量较高。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '制作Mojito时，尽量使用新鲜的青柠和薄荷叶，以保证最佳风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '糖浆的用量可以根据个人口味进行调整，喜欢更甜的可以适当增加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '在加入苏打水之前，先搅拌一下，可以使饮品更加均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '如果喜欢更清爽的口感，可以在最后加一片青柠片作为装饰。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '冰糖的用量可以根据个人口味进行调整，喜欢甜一些可以多加一些冰糖。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '冷藏腌渍后的冬瓜出水量较多，无需额外加水，直接熬制即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '熬制过程中注意观察，避免糊锅，同时也要保证熬制时间足够，以达到理想的浓稠度和颜色。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '冬瓜茶液冷藏保存，建议在1周内喝完，以保证最佳口感和卫生安全。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '饮酒有害健康，未成年人禁止饮酒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '可乐桶因冰块和可乐的口感掩盖了威士忌的酒味，因此不善酒力的人也容易在不知不觉中过量饮酒，请在保证个人与饮酒者的安全下调配。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '使用冰镇过的可乐可以使饮品更加清爽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '如果喜欢更甜的口感，可以适量加入糖浆或蜂蜜。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '在加入沸水后，尽量保持杯子内部温暖，例如使用开口较小的杯子或盖上盖子。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '如果气温较低时，使用量杯量取可能导致沸水在冲入红茶前冷却，则可以不使用量杯量取而直接估计其体积。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '可以根据个人口味调整糖和奶的比例，以达到最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '选择成熟的芒果和新鲜的葡萄柚，可以使甜品更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '奇亚籽可以用西谷米代替，但需要提前煮熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '如果喜欢更凉爽的口感，可以将所有材料提前冷藏。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '酸梅汤冷藏后口感更佳，建议放入冰箱冷藏至少1小时后再饮用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '如果没有方糖，可以用白糖代替，但用量可能需要适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '添加少量白酒可以增加风味层次，但请勿过量，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '酸梅晶固体饮料的品牌和成分可能有所不同，请根据包装说明调整用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '饮酒有害健康，未成年人禁止饮酒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '枫糖浆是可选项，可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '使用新鲜柠檬汁可以使饮品更加清新。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '冰块的选择也很重要，大块冰块能使饮品保持更长时间的冷度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '鸭肉焯水时一定要去除浮沫，这样可以去除腥味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '啤酒的选择可以根据个人口味调整，淡色啤酒会使菜肴更清爽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '炖煮过程中要注意观察水量，如果发现水量不足可以适量加热水或啤酒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '调味品的用量可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '选择新鲜的兔肉，肉质更加鲜嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '炸制过程中要注意火候，避免炸糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '辣椒和花椒的比例可以根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '放置一夜后食用，味道更加浓郁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '加入生姜爆香的同时能防止鸡翅粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '最后收汁时勿开过大火，防止味道偏苦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '本菜品偏甜，可根据个人口味调整糖的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '如果喜欢更浓郁的味道，可以在最后收汁时加入少许蜂蜜或麦芽糖。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '想让肉更有层次可以在生粉中加鸡蛋，炸出来会更香脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '炸肉时油温控制很重要，第一次炸时油温不宜过高，复炸时油温要高一些', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '酱汁的浓稠度可以根据个人口味调整，喜欢酸甜口味的可以适当增加糖和醋的比例', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '商芝属于小地方不特别有名的特产，至少本人在其他地方没有见到过，在制作时可换成其他蕨类蔬菜。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '炸肉时要注意安全，防止油溅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '蒸制过程中注意火候，先旺火后小火，使肉质更加酥烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '如果遵循本指南的制作流程而发现有问题或可以改进的流程，请提出 Issue 或 Pull request 。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '牛肉腌制时可以加少许料酒去腥增香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '炒牛肉时火候要大，快速翻炒以保持肉质嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '孜然和辣椒颗粒可以提前混合好，方便撒入锅中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '青椒丝最后加入，保持其脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '五花肉切片时尽量保持均匀，以便烹饪时受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '腌制时间越长，肉质越入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '辣椒斜刀切可以更好地释放辣味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '油温不宜过高，以免外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '豆豉和豆瓣酱要炒出香味，但不要炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '大火快炒可以保持辣椒的脆爽口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '趁热食用，风味更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '小米辣非常辣，可以根据个人口味适量增减。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '炒肉时火候要适中，不要炒得太久，以免肉质变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '豆瓣酱炒出红油后再加入其他食材，味道会更香浓。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '如果喜欢更浓郁的味道，可以适量加入一些老抽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '裹粉阶段务必把红薯淀粉揉散，杜绝干粉颗粒，否则高温炸制时易爆油溅烫。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '若一次制作较多，初炸后可沥油冷却，密封冷冻保存；食用前无需解冻，直接180°C复炸120秒即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '油温判断无温度计时：150°C≈竹筷插入边缘持续冒细泡；180°C≈插入即剧烈翻腾冒浓泡。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '本菜谱未含蘸料，传统可配椒盐、番茄酱或蒜泥醋汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '牛肉腌制时可以加入少许料酒去腥增香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '炒牛肉时火候要快，以保持牛肉的嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '尖椒可以根据个人口味选择辣度，喜欢辣的可以选择辣味较重的品种。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '炸肉片时，表面微焦即可，注意控制火候。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '起锅前也可以打个薄薄的水淀粉勾芡，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '可以根据个人口味调整调料用量，如喜欢酸一点可以多加点醋。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '煮肘子时，可以加入几片姜和少许料酒去腥。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '蒸肘子时，可以在锅底铺一层白菜叶，防止肘子直接接触锅底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '如果喜欢更浓郁的味道，可以在蒸肘子时加入一些五香粉或其他香料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '烤制时可以将鸡肉淋上蜂蜜或其他烤肉酱提升口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '烤箱预热至180度，烤制时间根据鸡肉的大小和厚度而定，需确保鸡肉熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '鸡肉必须全熟才能吃，吃未全熟的鸡肉可能会导致食物中毒和感染细菌，如沙门氏菌和福氏杆菌等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '血肠要提前处理好，避免煮的时候爆开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '酸菜要充分清洗干净，去除多余的盐分。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '排骨焯水可以去除腥味，使汤汁更清澈。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '使用电压力锅可以节省烹饪时间，但也可以用普通锅具炖煮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '蘸料可以根据个人口味进行调整，增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '炸糊也可以用来炸鸡腿、炸鱼等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '如果喜欢更酥脆的口感，可以用面包糠代替炸糊，但风味会有所不同。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '炸制过程中注意火候，避免油温过高导致外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '垫底蔬菜可根据口味替换为蘑菇、白菜、油麦菜等耐煮绿叶菜。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '刀口辣椒若嫌繁琐，可用15g干辣椒段+3g青花椒直接替代撒面。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '肉片滑嫩核心三要素：血水洗净挤干、单向搅打上劲、蛋清+淀粉+油三重保水。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '本做法亦适用于水煮牛肉，仅需将里脊肉替换为牛里脊或牛腿肉，其余流程一致。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '猪肉片可以选择稍微冷冻一下再切，这样更容易切得薄而均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '调味料可以根据个人口味适当调整，喜欢酸甜口味的可以多加一些番茄酱。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '炒洋葱时火候不宜太大，以免外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '使用茶匙和大匙来精准确定用料的量，可以使菜品更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '可以在腌制鸡翅时加入一些切碎的大蒜和生姜，增加香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '烤制过程中，如果发现鸡翅表面过于干燥，可以刷上一层薄薄的蜂蜜水，增加光泽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '烤箱温度和时间可能因型号不同而有所差异，请根据实际情况适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '大火收汤时，注意不要糊锅，可以适当翻动来检查水位。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '调味的技巧，最后加盐时，可以一点一点加入，搅拌后品尝味道，直到可以接受的口味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '酸菜的酸度可以通过冲洗次数来调节，喜欢酸味可以少冲洗几次，不喜欢酸味可以多冲洗几次。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '本品口感微辣，辣度可通过调整辣椒粉用量控制（不建议超过30g）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '甜椒粉主要用于增色与风味，无明显辣感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '鸡全翅指完整鸡翅（含翅尖、翅中、翅根）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '刚出炉锡纸盘温度极高，请务必使用夹子或湿抹布等隔热方式取用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '实际烘烤效果请根据自家空气炸锅功率灵活调整时间与温度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '考虑各个品牌的番茄酱内含盐量不同，建议在炒牛肉时少放盐，煮的时候尝一下再调味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '煮酱料期间请搅动，以免粘锅。如果酱料变粘稠就可以出锅啦！', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '可以根据个人口味，将碎牛肉替换成一半碎猪肉一半碎牛肉，牛奶替换成鸡汤或饮用水。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '粉条要提前浸泡至软，这样烹饪时更容易熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '五花肉切片要均匀，厚度适中，这样烹饪时更易入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '白菜帮子和嫩叶分开处理，可以更好地控制烹饪时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '小火慢炖可以使食材更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '收汁时要注意火候，避免糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '如需自制米粉：大米150g中小火炒至微黄（约8分钟），加干辣椒1g、花椒1g、八角0.5g炒香，料理机打碎后过筛备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '蒸制全程注意补水，避免干烧；补充热水温度需≥90°C，防止锅温骤降。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '本菜谱按2份设计（每份供3人），所有主料用量均为2份总量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '里脊肉切条时尽量保持大小一致，以便均匀炸制。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '裹粉时要抖掉多余的淀粉，防止炸制时粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '炸制时注意火候，第一次炸至微黄，第二次复炸使表皮酥脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '调酱汁时可以尝一下味道，根据个人口味调整酸甜度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '猪肉末可以选择稍微带点肥肉的，这样蒸出来的肉饼更加鲜嫩多汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '蒸制过程中不要频繁开盖，以免影响蒸制效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '可以根据个人口味调整调料用量，如喜欢更咸一些可以适当增加生抽的量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '建议使用单晶冰糖，口感更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '腐乳自带咸鲜，不用额外放盐', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '大火收汁时要不断晃动锅体避免粘底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '五花肉焯水后要用温水冲洗干净并沥干水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '操作时，需要注意观察沸腾的水位线，如发现低于2/3的食材应加热水至没过食材。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '如果没有高压锅，可以使用普通锅，但炖煮时间需要延长至40分钟到1小时。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '羊肉焯水时一定要撇去浮沫，这样可以使汤更加清澈。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '调味时先尝一下汤的味道，再根据个人口味调整盐量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '选用五花肉薄片是因为切肉简单且无需腌制即可入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '加入食盐前建议尝味，根据个人口味增减盐量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '猪肘的选择很重要，新鲜的猪肘肉质更好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '油炸时一定要注意安全，防止烫伤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '炒糖色时要不断搅拌，防止糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '收汁时要不断搅拌，防止糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '可以根据个人口味调整调料用量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '粉丝不建议煮太久，易断且口感变差；若时间过长，应适当减少清水用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '郫县豆瓣酱含盐量较高，可根据口味酌情减少生抽用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '可加入0.5g白胡椒粉调味，提升风味层次。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '豆豉浸泡后稍微剁碎会更入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '蒸制时间随排骨大小调整，以筷子能轻松插入软骨处为准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '传统的豉汁排骨不放撒料和淋热油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '吃剩的汤汁可以用来拌饭或者拌面', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '本菜需一定火候控制能力，建议使用大火热锅快炒；', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '青椒务必选用新鲜脆嫩者，螺丝椒为风味最佳选择；', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '全程不建议新手省略干煸步骤，此为增香关键；', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '若调整份数，所有原料及油量（8ml/份）、时间参数不变，仅按比例缩放用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '选择新鲜的猪里脊肉，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '香干切丝前可以用热水焯一下，去除豆腥味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '如果喜欢辣味，可以在炒青椒时加入一些小米椒碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '根据个人口味调整盐和鸡精的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '鱼香味关键在‘葱姜蒜末+泡椒/豆瓣酱+糖醋比例’，本方以豆瓣酱替代传统泡椒，风味略有差异但可操作性强', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '所有刀工建议粗细均匀，确保受热一致', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '香汁务必提前调匀，临出锅前再淋入，保证复合味型不散', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '青菜和肉类的焯水时间不宜过长，以保持口感和营养。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '选择自己喜欢的麻辣香锅调料品牌，不同品牌的调料口味可能有所不同。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '可以根据个人口味调整干辣椒的数量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '炒制过程中火候要适中，避免食材炒焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '炒糖色时一定要小火慢炒，防止糊锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '如果没有干香菇，可以用新鲜香菇代替，但风味会略有不同。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '焖煮过程中可以适当加水，保持汤汁充足。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '青椒最后加入，保持其脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '腌制黄瓜时加盐可以去除多余水分，但要注意挤干水分后再炒制，以免过咸。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '炒制时火候要大，快速翻炒，以保持食材的鲜嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '根据个人口味调整辣椒的用量，喜欢辣的可以多放一些小米辣。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '凉皮和面筋在使用前最好先用冷水冲洗一下，去除多余的油脂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '调料的比例可以根据个人口味进行调整，喜欢酸一点的可以多加点醋，喜欢辣一点的可以多加点辣椒油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '绿豆芽焯水时间不宜过长，以免失去脆嫩的口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '芝麻酱的浓稠度可以根据个人喜好调整，喜欢稀一点的可以多加点水，喜欢稠一点的可以少加点水。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '如果使用微波炉加热，建议先将面条、酱料和水混合均匀，再进行加热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '可以根据个人喜好添加蔬菜、肉类等配料，丰富口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '注意控制火候，避免面条过软或过硬。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '操作时请擦干手上水滴！以免水进入油锅中发生爆炸！造成严重烧伤！', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '所有香料要提前准备好，确保烹饪过程顺利进行。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '炒制过程中要不断搅拌，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '如果喜欢更辣的口味，可以适当增加糍粑辣椒和干辣椒面的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '煮饺子时保持中火，避免大火导致饺子破裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '准备一些蘸料如黑醋、姜丝、香油和蒜泥，可以提升饺子的风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '煮完饺子后及时清洗锅具，避免面粉残留形成黏糊物质。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '烧开水的时间通常为5-10分钟，不需要长时间加热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '煮馄饨时，可以适当搅动以防止粘底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '如果没有电饭煲，也可以用普通锅具煮制，方法类似。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '可以根据个人喜好添加其他配料，如虾皮、紫菜等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '可预留少量蘑菇片用少许黄油单独煎至金黄，出锅前撒于汤面作装饰', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '使用鸡高汤代替清水可显著提升鲜味，但需控制总液体量≤300 ml/份', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '喜欢更浓稠口感可适量增加面粉（+2–5 g）或淡奶油（+10–20 ml）', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '建议现做现吃，不建议冷藏或冷冻保存，以免影响质地与风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '若汤体过稀可延长小火收汁时间；过稠可补少量温牛奶调节', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '小米只需用水去除浮灰，千万不可过分淘洗，以免损失小米油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '小米需要在水开的时候下锅，这样可以更好地释放小米的香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '不喜欢放碱的话，原汁原味的小米香更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '如果使用高压锅或电饭锅，水量要适当减少，一般100克小米加1800克水即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '剁肉时尽量剁得细一些，这样肉丸会更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '调味时可以根据个人口味适当增减调料的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '煮丸子时不要用大火，以免丸子外皮煮老而内部未熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '如果喜欢辣味，可以在最后加入适量的辣椒油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '可以根据口味加入适量的醋或糖来调整口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '如果喜欢辣味，可以加入适量的辣椒或辣椒酱来调味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '牛肉切片时尽量顺着纹理切，这样煮出来的牛肉更加嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '提前一晚准备好主料，第二天早上再添加配料和酱料，可以节省早晨的时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '如果喜欢更浓郁的口感，可以在煮粥时加入少量糯米。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '煮粥时可以适量加一些白胡椒粉，增加香气和暖胃效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '煮粥时要不断搅拌，防止粘底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '可以根据个人口味添加适量的盐或糖调味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '如果喜欢更加香滑的口感，可以在煮粥前将米浸泡30分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '为了使蛋花更加嫩滑，可以在蛋液中加入少许水或淀粉。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '如果喜欢浓稠口感，可在汤中加入2g淀粉水勾芡。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '可以根据个人口味添加其他配料，如豆腐、蘑菇等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '番茄尽量不用新鲜番茄代替，番茄罐头+番茄膏的组合风味更足', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '除了胡萝卜、洋葱、欧芹、牛肉是必备食材外，其余可自由搭配', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '炖煮过程中注意火候，保持中小火，避免汤汁过于浓稠', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '往粥锅加入食材时，应当进行搅拌，使食材原料均匀分布在各处，并注意观察水位线，如发现水位线低于米线及食材应立即补水。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '注意控制火候，不要过大，定时搅拌。如果使用普通锅，建议烧开水后再下原料，搅拌到再次烧开改小火，避免锅底烧糊。如果有条件，建议改用高压锅或粥锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '西红柿选择成熟度高的，味道会更鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '鸡蛋液要充分搅拌均匀，这样做出的蛋花才会细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '加水时可以根据个人喜好调整水量，喜欢浓稠的可以少加一些水。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '如果不喜欢味素，可以不加，或者用鸡精代替。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '金针菇煮的时间不宜过长，以免失去口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '可以根据个人口味添加一些葱花或香菜增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '如果不喜欢味精，可以换成鸡精或其他调味料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '煲汤盅很烫，拿的时候小心别烫到或者手滑摔破。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '广东老火靓汤讲究用料和火候，只要备好料和炖够一定时辰，就算大功告成！', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '如果使用电子煲汤盅，可以选择“煲汤”模式，时间设置为1.5小时。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '黄瓜可根据喜好决定是否去皮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '黄瓜薄片可用刮皮刀刮制更薄更匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '皮蛋切块时抹少量香油可防止粘刀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '推荐使用猪油提升焦香风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '使用隔夜饭可以使炒饭更加松散，不易结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '如果喜欢干一点的炒饭，可以在最后一步多炒一会儿。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '如果嫌麻烦，可以在第一步直接放3个鸡蛋，取消挖洞打另一个鸡蛋的步骤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '根据个人口味调整豆瓣酱的用量，可以增加或减少辣度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '炒好的咸肉和菜梗铺在饭上后，煮饭全程严禁搅动', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '不推荐使用‘家乡鲜肉’类高盐咸肉；若使用，建议瘦肉部分切丁后浸泡于5%糖水20分钟脱盐', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '锅巴形成依赖电饭煲底部加热效率与焖制时间，焖足5分钟是关键', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '参考资料：咸肉菜饭 - 维基百科', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '煮水饺不需要盖锅盖，加三次水就是为了不让饺子一直处于沸腾状态导致表皮破损变成面片。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '考虑搭配黑醋食用。建议用量：10-20ml。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '考虑姜切丝，在小碗加入 20ml 的黑醋与姜丝搅拌当蘸料，味道更丰富。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '考虑搭配黑醋时加入 1~3 滴香油，搅拌当蘸料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '考虑搭配黑醋时加入砸好的蒜泥，搅拌当蘸料。（口腔内会残留蒜味，若饭后需要与他人面对面谈话建议放弃或清洁口腔）', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '可以根据个人喜好添加其他喜欢的食材，如虾仁、鸡肉等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '如果掌握不好加盐量，可采用少量多次添加的方法，以免过量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '面条的选择可以根据个人喜好来定，不同类型的面条口感各异。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '煮面时保持适当的火力，避免面条煮得太软或太硬。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '煮年糕时要不断搅拌，以免粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '炸葱白时要用小火，避免炸糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '翻炒年糕时火候要大，动作要快，以免年糕粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '最后加入葱油可以使年糕更加香滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '辅料可以根据个人喜好添加，如瘦肉等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '可以根据个人口味添加蔬菜，如胡萝卜丝、青椒丝等，增加营养和口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '火候控制很重要，中小火炒制可以避免食材糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '调料的比例可以根据个人口味进行调整，喜欢重口味的可以适当增加调料量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '河粉炒料可以根据个人口味调整，如果使用市售河粉料，注意查看成分表，避免重复加盐。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '炒河粉时火候要适中，避免糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '食材的准备可以提前完成，这样炒制时更加流畅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '根据个人口味，可以适当添加辣椒或其他调料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '炒的过程中要注意控制火候，以防炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '如果火太大，可以将火调小，沿锅边加油润锅或洒水，注意不要全倒在一个地方，最好分散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '调味料可根据个人喜好加入其他香料，如南德调味料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '如果喜欢吃脆的，可以将火开到最小，多翻炒一会，关火后趁锅热再放置一会再倒出，更香脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '辅料也可根据个人口味加入蒜末、蒜苗等，可以单独爆香后再混合。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '肉丁可以选择稍微带点肥肉，这样炒出来的酱更香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '豆瓣酱和甜面酱的比例可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '煮面时不要煮得太软，保持一定的劲道口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '炒酱时要用中小火，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '菜码可以根据季节和个人喜好进行调整，如豆芽、芹菜等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '碱水面焯烫后可以过一下凉水，再沥干水分，这样面条更加爽滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '蒜水可以用蒜末加适量水浸泡半小时制成，也可以直接用蒜泥加水调制。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '肉汤汁可以用猪骨或鸡骨熬制，也可以用市售的高汤代替。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '芝麻酱要选择纯正的芝麻酱，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '热干面最好现做现吃，以保持最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '如果使用白砂糖、淀粉组合代替蜂蜜，一定要让白砂糖和淀粉完全溶解再下锅，否则容易糊锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '焖煮时每隔3-5分钟翻搅一下，避免局部过热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '如果酱汁冒大泡、颜色变深褐，或边缘出现细密焦糖结晶，立即关火。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '提前准备好所有食材和调料，可以提高烹饪效率。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '米饭提前煮好，保持温热，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '可以根据个人口味添加其他食材，如火腿肠、生菜、小肉丝等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '煮面时保持中小火，避免水溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '如果喜欢更浓郁的味道，可以在煮面时加入一些牛奶或高汤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '米饭最好选择新鲜煮好的，这样口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '猪油可以用微波炉稍微加热一下，使其更容易融化。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '调味料可以根据个人口味进行调整，喜欢更咸一点的可以多加一些生抽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '建议搭配瘦肉和蔬菜食用来均衡营养。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '高胆固醇，不建议经常食用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '选择中等粗细的挂面，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '过冷水可以让面条更加爽滑，不易粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '可以根据个人口味添加葱花、蒜末等其他调料提升风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '如果喜欢甜口，可以在碗汁中增加10g糖。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '确保做完饭后关闭燃气设备，防止发生危险。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '肉馅可以选择肥瘦相间的猪肉馅，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '鸡蛋打入锅中后不要立即搅拌，保持完整形状更美观。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '炸葱油全程务必使用小火，是激发葱香、避免焦苦的关键。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '葱油酱汁冷藏可保存7–10天；使用前无需加热，直接取用即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '本配方基础酱汁量适配4份（每份80 g干面+15 ml酱汁），实际可根据口味微调酱汁用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '切割猪肉可请菜市场摊贩代劳，建议在已切割但未付款前提出，成功率最高', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '首次制作建议提前备料（Mise en place），熟练后可并行处理（如蒸面同时炖卤）', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '两次蒸制前均须将面条彻底散开，防止蒸后结团；蒸屉取出时动作轻缓，避免倾覆触水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '佐餐推荐啤酒，风味更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '本方为豫南口味，地域差异属正常，以‘好吃即可’为最终标准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '炒饭建议使用隔夜饭，水分较少，不易粘锅，口感更松散有嚼劲。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '打蛋时加入牛奶可显著提升蛋皮的嫩滑度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '全程蛋皮操作需保持小火，中大火易导致底部焦黑、上层未凝固。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '如包裹失败，可直接将炒饭铺于盘中，覆盖一层薄蛋皮（半熟时倾倒其上，静置10秒定型），同样美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '使用隔夜冷饭炒饭效果最佳，因为冷饭已经流失了一部分水分，更容易炒得粒粒分明。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '炒饭时火候要大，快速翻炒，避免米饭粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '调味料可以根据个人口味进行调整，但不要过量，以免掩盖食材本身的味道。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '可以加入其他喜欢的配料，如豌豆、玉米等，增加口感和营养。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '如果想要更有嚼劲的粉，可以缩短第二步煮粉的时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '如果想在螺蛳粉中添加炸蛋，请参考炸蛋的教程。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '配料的选择请依照个人口味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '如果您遵循本指南的制作流程而发现有问题或可以改进的流程，请提出 Issue 或 Pull request 。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '提前浸泡蕨根粉可以使煮制时间缩短，且不易粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '过冷水是关键步骤，可以使蕨根粉迅速降温并防止粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '调味时要根据个人口味逐步调整，确保味道均衡。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '建议使用碗作为最终装盘餐具，方便食用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '如果喜欢更浓稠的口感，可以减少水量至500毫升', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '枸杞可以提前泡软，这样口感会更好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '可以根据个人喜好添加其他配料，如红枣、桂圆等', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '韭菜切碎后可以撒一点盐，挤出多余的水分，这样馅料不会太湿。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '煎制时火候不宜过大，以免外焦内生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '可以根据个人口味添加豆腐干等配料，增加口感层次。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '烧卖皮与馅比例宜控制在1:2–1:2.5（重量比），确保皮薄馅足', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '皮冻是多汁关键，推荐自制（猪皮+水+姜葱炖煮后冷藏凝结），市售皮冻注意选无添加者', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '蒸好后趁热蘸玫瑰米醋最佳，亦可配桐乡辣酱、油泼辣子、生抽+姜丝', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '冷冻保存：生坯平铺冷冻定型后装袋，-18℃可存1个月；蒸前无需解冻，直接延长蒸制时间', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '绞肉机建议中档，避免过细失Q弹，或手工剁制更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '可以根据个人口味添加一些葱花或芝麻，增加香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '如果喜欢辣味，可以加入一些辣椒油或辣椒酱。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '选择品质好的麻油，可以让这道菜更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '煮面时注意火候，不要让面条煮得太软，保持一定的嚼劲更好吃。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '一定要选择半干荞麦面，口感最好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '可以根据个人口味添加其他食材，如火锅丸、蛋饺等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '火锅底料、花生酱和牛奶是这道菜的关键调味品，不可省略。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '如果不能吃酸，可以不加醋。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '煮面时注意火候，避免面条煮得太软或太硬。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '油麦菜焯水后过冷水，可以保持其脆嫩口感和鲜艳色泽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '调味汁可以根据个人口味适当调整，喜欢酸一点可以多加点醋，喜欢甜一点可以多加点糖。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '拌好的凉拌油麦菜最好现做现吃，以保证最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '建议选用质地较硬的北豆腐或老豆腐，不易碎裂，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '如喜清淡口感，可省略醋和辣椒油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '酱汁比例可根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '焯水后若不过凉水，豆腐易烫口且余热影响酱汁风味；虽原文未提，但属合理实践建议。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '金针菇焯水时间不宜过长，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '酱汁的比例可以根据个人口味喜好进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '如果不喜欢吃辣，可以省略辣椒油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '黄瓜去皮与否可根据个人喜好决定，去皮口感更细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '若想让凉拌黄瓜更加清凉爽口，可提前将黄瓜冷藏后再进行制作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '腌制后的黄瓜建议尽快食用完毕，长时间放置会导致黄瓜失去清脆感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '调料比例可以根据个人口味适当调整，比如喜欢酸一点就多加点醋，喜欢咸一点则可适量增加酱油或盐的量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '茄子和土豆切块后可以先用淡盐水浸泡，防止氧化变色。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '煎炸时火候不宜过大，以免外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '调味品的用量可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '煎豆腐时油温要控制好，防止外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '裹粉时要抖掉多余的粉，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '蔬菜切得均匀，烹饪时熟度一致。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '大火快炒蔬菜，保持其脆嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '调味料要均匀分布，确保味道均衡。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '松仁可以提前用小火干炒至微微金黄香脆，更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '使用罐头玉米时应先沥干水分，避免炒制过程中出水过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '炒制时火候不宜过大，以防糊锅或松仁焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '不确定咸淡的情况，可以先少放盐，在出锅前尝味，考虑调整加盐。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '可以用鸡汤、骨头汤等替代水，味道会更加鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '焖的时间不可过长，以免蔬菜变得过于软烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '选择新鲜的蔬菜，口感和营养都会更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '选择新鲜的鸡蛋，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '香醋的选择对这道菜的味道至关重要，推荐使用老恒和酿造香醋。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '火候掌握好，鸡蛋不要炒得太老，保持嫩滑口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '可以根据个人口味调整辣度和甜度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '提前将花菜焯水可以缩短炒制时间，并使花菜更容易熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '炒制时间可以根据个人喜欢的花菜软硬程度调整。喜欢脆一些可以缩短时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '如果喜欢口感更脆，可以在炒制过程中不加水，直接翻炒至熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '花菜焯水后立即捞出并用冷水冲凉，可以保持其脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', '南瓜的品种不同，甜度和口感会有差异。老南瓜通常更甜更面。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', '南瓜皮含有营养，如果喜欢也可以不去皮蒸，但需要彻底洗净。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', '蒸的时间取决于南瓜块的大小和厚度，以及南瓜的品种。用筷子测试是判断是否蒸熟的好方法。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '因为酱油的缘故，所以本菜不必加盐。出锅之前可以尝一下，如果不咸可以加微量的盐，下次炒时酱油量要增加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '如果加了虾皮，可以将酱油量酌情减少。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '炒本菜时，一直大火即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '切忌！一定不可加水，会变成水煮茄子，口感差，所以油可多放，不可少放。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '如果家用灶达到7成油温后温度不再继续明显上升，可直接进行下一步，不必强求9成油温。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '选择新鲜的青菜是关键，叶片应饱满且无黄叶。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '炒青菜时火候要大，动作要快，以保持青菜的脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '加盐的时间不宜过早，以免青菜出水过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '如果喜欢口感更脆，可以省略加水步骤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '豆腐先焯水去豆腥味可以去除豆腥味，但内酯豆腐本身较为细腻，不焯水也可以。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '皮蛋切瓣时刀上可以抹点香油防止粘刀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '可以根据个人口味调整调料的比例，如喜欢酸一些可以多加些醋，喜欢辣一些可以多加些辣椒油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '豆角一定要炒至断生再加调料汁，否则容易夹生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '焖制时注意火候，避免豆角过于软烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '调味料的比例可以根据个人口味进行微调。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '茄子切好后用盐腌制可以去除多余的水分，使炸出来的茄子更加酥脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '炸茄子时要控制好油温，太高容易炸糊，太低则会吸油过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '炒香调料后再加入其他食材，可以使菜肴更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '加水量要适中，太多会使菜肴过于稀薄，太少则会影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '炖煮过程中要注意观察汤汁的浓稠度，适时调整火力。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '选择质地较硬的老豆腐，更容易成型且不易碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '煎豆腐时火候不宜过大，以免外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '酱料中的玉米淀粉可以使酱汁更加浓稠，提升口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '可以根据个人口味调整酱料的比例，如喜欢更甜或更咸。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '茄子和土豆切块大小要一致，以便同时熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '炒制过程中注意火候，避免食材焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '可以根据个人口味调整辣椒和盐的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '炖煮时保持中小火，确保食材软糯入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '选择质地较硬的北豆腐更适合煎制，不易碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '煎豆腐时火候不宜过大，以免外焦内生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '可以根据个人口味添加其他调料，如生抽、蚝油等增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '焯水时间不宜超过推荐时长，以免影响西兰花的口感和营养。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '如喜更脆口感，可将焯水时间缩短至1.5-2分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '蒜末务必小火煸炒，避免高温焦苦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '茄子削皮后容易氧化变黑，可以在水中浸泡一会儿，防止氧化。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '蒲烧汁的制作方法：将生抽、老抽、糖、料酒、水按比例混合，小火熬制至浓稠即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '煎茄子时可以用厨房纸巾吸去多余的水分，防止溅油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '如果喜欢更浓郁的味道，可以适当增加蒲烧汁的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '生菜焯水时间要控制好，避免过熟影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '调汁时可以根据个人口味适当调整调料的比例。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '蒜末炒至金黄色时香味最佳，但注意不要炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '西红柿去皮后口感更佳，但也可以不去皮，根据个人喜好决定。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '鸡蛋液中加入少量醋可以使鸡蛋更加蓬松，但不加也无妨。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '炒鸡蛋时火候不宜过大，以免鸡蛋变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '西红柿炒至软烂时再加入鸡蛋，可以使菜肴更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '调味料的用量可以根据个人口味适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '清洗土豆丝淀粉一定要去干净，不然会全黏在一起。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '加入蒜末、盐后应尽快出锅，保留蒜香以及避免破坏口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '可以根据个人口味调整辣椒的数量，喜欢更辣的可以增加干辣椒的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '炒制过程中火候要大，动作要快，以保持土豆丝的脆爽口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '金针菇一定要先炒软，这样更易入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '豆腐尽量不要翻炒，以免破碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '可以根据个人口味调整小米椒的数量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '收汁时注意观察，避免糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '推荐使用不粘锅，使用不粘锅时初次放油可以减少5ml。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '应确保鸡蛋剥皮时已经完全凝固。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '不宜过度翻炒，容易散。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '不能吃辣的可以减少小米辣的用量，还可以剔除辣椒籽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '豆角和土豆的切块大小要尽量一致，这样烹饪时能更好地同步熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '熬制过程中要保持小火，耐心等待食材慢慢变软，这样味道会更加浓郁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '可以根据个人口味调整调料的用量，如喜欢酸味可以多加一些西红柿。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '皮蛋可以提前冷藏，这样更容易去皮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '煎青椒时要用小火慢煎，使其更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '调味料的比例可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '如果喜欢口感更细腻，可以选择方法1；如果追求方便，可以选择方法2。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '火腿本身含盐，需先调味再加入火腿，防止整体过咸', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '黄瓜不宜久炒，以保持清脆口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_additional_note (recipe_id, note, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '鸡蛋用筷子划散可使成品更细嫩松散', '2025-12-28 19:17:19', '2025-12-28 19:17:19');

-- ==================== t_favorite ====================

INSERT INTO t_favorite (user_id, recipe_id, created_at) VALUES ('edf884e26f0b29eda78ef24313f6e865', 'I7bMML3zzHX3nZXKS7NfMP', '2025-12-13 21:06:00');
INSERT INTO t_favorite (user_id, recipe_id, created_at) VALUES ('edf884e26f0b29eda78ef24313f6e865', 'SEBSUOuPRAM80pXiq56w9Y', '2025-12-13 21:45:05');
INSERT INTO t_favorite (user_id, recipe_id, created_at) VALUES ('edf884e26f0b29eda78ef24313f6e865', '0PXxUBY0ZsWJMpFWcyWh14', '2025-12-13 21:45:10');
INSERT INTO t_favorite (user_id, recipe_id, created_at) VALUES ('edf884e26f0b29eda78ef24313f6e865', 'baVPKaRRkUGB2RJIqWcYpr', '2025-12-13 21:45:14');
INSERT INTO t_favorite (user_id, recipe_id, created_at) VALUES ('edf884e26f0b29eda78ef24313f6e865', 'Y5tNfPJr4ZriE5wNU0m7IM', '2025-12-13 21:45:18');

-- ==================== t_ingredient ====================

INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '青蟹（肉蟹）', 'seafood', 1.0, 'g', '选择新鲜、活力强的螃蟹', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '咖喱块', 'sauce', 15.0, 'g（一小块）', '推荐使用乐惠蟹黄咖喱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '洋葱', 'vegetable', 200.0, 'g', '中等大小的一个', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '椰浆', 'other', 100.0, 'ml', '选择无糖的椰浆', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '鸡蛋', 'egg_dairy', 1.0, '个', '仅用蛋清', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '生粉（淀粉）', 'dry_goods', 5.0, 'g', '用于封住蟹黄', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '大蒜', 'vegetable', 5.0, '瓣', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '鳝丝', 'seafood', 400.0, 'g', '让摊主帮忙宰杀，保留一些血水', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '大蒜', 'vegetable', 80.0, 'g（切末）', '一半用于炒制，一半用于最后撒在表面', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '姜末', 'spice', 20.0, 'g', '新鲜生姜切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '料酒', 'seasoning', 13.0, 'g', '分两次使用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '生抽', 'sauce', 3.0, 'g', '用于调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '蚝油', 'sauce', 2.0, 'g', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '老抽', 'sauce', 2.0, 'g', '上色用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '食用盐', 'seasoning', 2.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '白糖', 'seasoning', 6.0, 'g', '根据个人口味调整，建议使用10g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '胡椒粉', 'spice', 3.5, 'g', '分两次使用，建议使用6g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '淀粉', 'dry_goods', 10.0, 'g', '用于勾芡', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '水', 'other', 50.0, 'g', '与淀粉混合成水淀粉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '葱花', 'vegetable', 15.0, 'g', '用于最后撒在表面', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '猪油', 'oil', 20.0, 'g', '用于最后浇油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '黑鳕鱼', 'seafood', 450.0, '片', '选择新鲜、无异味的鱼肉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '青葱', 'vegetable', 35.0, 'g', '选择新鲜、绿色的青葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '姜', 'spice', 16.0, 'g', '选择新鲜、无霉变的生姜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '料酒', 'seasoning', 5.0, 'mL', '选用优质料酒', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '酱油', 'sauce', 25.0, 'mL', '选用生抽或淡色酱油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '芝麻油', 'oil', 2.0, 'mL', '选用纯正芝麻油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '花生油', 'oil', 50.0, 'mL', '选用无味的植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '巴沙鱼', 'seafood', 500.0, 'g', '选择新鲜的巴沙鱼', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '花菜', 'vegetable', 300.0, 'g', '洗净切成小朵', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '生菜', 'vegetable', 200.0, 'g', '洗净备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '红油豆瓣酱', 'sauce', 40.0, 'g', '根据口味可增减', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '豆豉', 'sauce', 10.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '藤椒油', 'oil', 10.0, 'ml', '增加麻味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '菜籽油', 'oil', 25.0, 'ml', '分次使用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '白胡椒粉', 'spice', 3.0, 'g', '提味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '大蒜', 'vegetable', 2.0, '瓣', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '盐', 'seasoning', 5.0, 'g', '腌制和调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '糖', 'seasoning', 2.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '生蚝', 'seafood', 6.0, '个', '选择新鲜、壳紧闭的生蚝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '葱', 'vegetable', 3.0, '颗', '切葱花备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '蒜', 'vegetable', 6.0, 'g', '剁成蒜末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '姜', 'spice', 1.0, 'g', '切成细丝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '酱油', 'sauce', 30.0, 'ml', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '鲫鱼', 'seafood', 1.0, 'g', '选择新鲜的鲫鱼，去鳞、去内脏、洗净', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '姜', 'spice', 10.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '蒜瓣', 'vegetable', 15.0, 'g', '拍碎或切片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '干辣椒', 'spice', 2.0, '个', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '油', 'oil', 50.0, 'ml', '食用油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '盐', 'seasoning', 10.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '料酒', 'seasoning', 30.0, 'ml', '用于去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '醋', 'seasoning', 5.0, 'ml', '可根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '酱油', 'sauce', 15.0, 'ml', '老抽调色，生抽调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '白砂糖', 'seasoning', 10.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '葱', 'vegetable', 1.0, '根', '切葱花', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '香菜', 'vegetable', NULL, '适量', '装饰用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '小米椒', 'spice', 1.0, '个', '切碎，可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '味精', 'seasoning', 5.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '蚝油', 'sauce', 5.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '鱼头', 'seafood', 1.0, 'g', '推荐使用花鲢鱼头，口感更佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '大葱', 'vegetable', 200.0, 'g', '切段和切碎分开处理', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '姜', 'spice', 80.0, 'g', '切片，厚度约3mm', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '大蒜', 'vegetable', 3.0, '瓣', '拍碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '美人椒', 'vegetable', 1.0, '个', '切圈，厚度约3mm', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '香菜', 'vegetable', 4.0, '棵', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '八角', 'spice', 2.0, '个', '稍微冲洗', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '干辣椒', 'spice', 5.0, '个', '切四段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '油', 'oil', 30.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '盐', 'seasoning', 7.0, 'g', '腌制用5g，烹饪用2g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '鸡精', 'seasoning', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '生抽', 'sauce', 15.0, 'g', '腌制用10g，烹饪用5g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '老抽', 'sauce', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '陈醋', 'sauce', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '黑胡椒粉', 'spice', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '料酒', 'seasoning', 15.0, 'g', '腌制用10g，烹饪用5g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '鲤鱼', 'seafood', 1.5, '斤', '选择新鲜的鲤鱼，让卖家处理好', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '五花肉', 'meat', 100.0, 'g', '切成薄片', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '大葱', 'vegetable', 2.0, '根', '切段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '姜', 'spice', 80.0, 'g', '切片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '大蒜', 'vegetable', 3.0, '瓣', '拍碎切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '干辣椒', 'spice', 2.0, '个', '切段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '油', 'oil', NULL, '适量', '用于炸鱼和炒料', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '盐', 'seasoning', 1.0, '茶匙', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '生抽', 'sauce', 50.0, 'ml', '提味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '老抽', 'sauce', 20.0, 'ml', '调色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '陈醋', 'sauce', 50.0, 'ml', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '蚝油', 'sauce', 5.0, 'ml', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '料酒', 'seasoning', 50.0, 'ml', '去腥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '白糖', 'seasoning', 50.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '肉蟹', 'seafood', 500.0, 'g', '推荐优先级：缅甸黑蟹 > 青蟹 > 梭子蟹 > 大闸蟹；务必去除蟹胃、蟹腮、蟹心；冷冻蟹需半解冻后处理', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '虾', 'seafood', 200.0, 'g', '可选；若添加，需追加大蒜10 g、食用油10 ml、白胡椒粉1 g、啤酒50–100 ml、清水200 ml', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '土豆', 'vegetable', 450.0, 'g', '切3 cm见方块', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '年糕', 'staple', 200.0, 'g', '推荐硬年糕；切1 cm厚片，泡冷水备用，下锅前冲洗，下锅时置于表面防糊', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '洋葱', 'vegetable', 100.0, 'g', '切3 cm宽月牙瓣', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '大蒜', 'vegetable', 20.0, 'g', '若加虾则为30 g；切片或拍碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '生姜', 'vegetable', 15.0, 'g', '切片或拍碎', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '干辣椒', 'spice', 5.0, 'g', '根据辣度调整；剪段去籽可减辣', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '青椒', 'vegetable', 30.0, 'g', '切边长4 cm菱形片', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '红椒', 'vegetable', 30.0, 'g', '切边长4 cm菱形片', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '蚝油', 'sauce', 20.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '海鲜酱', 'sauce', 15.0, 'g', '可选；替代方案：蚝油12 g + 白砂糖3 g', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '黄豆酱', 'sauce', 15.0, 'g', '可选；替代方案：生抽12 ml + 老抽2 ml + 白糖1 g', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '甜面酱', 'sauce', 10.0, 'g', '可选；替代方案：白糖5.5 g + 生抽4 ml + 老抽0.5 ml；或用烧烤酱等量替代', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '番茄酱', 'sauce', 10.0, 'g', '没有可用半颗番茄挤汁碾碎替代', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '淀粉', 'dry_goods', 40.0, 'g', '玉米淀粉或土豆淀粉；用于裹蟹；裹粉前螃蟹须擦干', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '冰糖', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '鸡精', 'seasoning', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '白胡椒粉', 'spice', 2.0, 'g', '若加虾则为3 g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '料酒', 'seasoning', 15.0, 'ml', '可用黄酒等量替代', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '生抽', 'sauce', 20.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '老抽', 'sauce', 5.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '啤酒', 'other', 200.0, 'ml', '若加虾则为250–300 ml', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '清水', 'other', 800.0, 'ml', '若加虾则为1000 ml', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '食用油', 'oil', 30.0, 'ml', '爆香及炖煮用；若加虾则+10 ml；另备炸制用油500 ml（180–200 °C）', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '螃蟹', 'seafood', 500.0, '只', '首选河蟹，次选梭子蟹', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '豆瓣酱', 'sauce', 30.0, 'g', '根据口味调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '冰糖', 'seasoning', 0.0, 'g', '可选，用于调节甜度', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '老抽', 'sauce', 15.0, 'ml', '用于上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '菜油', 'oil', 20.0, 'ml', '未脱色的菜籽油，俗称“毛菜油”或“土菜油”，备选花生油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '番茄酱', 'sauce', 15.0, 'ml', '可选，增加酸甜味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '料酒', 'seasoning', 5.0, 'ml', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '老姜', 'vegetable', 10.0, 'g', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '小葱', 'vegetable', 10.0, 'g', '切段，葱白和葱绿分开使用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '鸡蛋', 'egg_dairy', 1.0, 'g', '可选，敲入盘底', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '猪肉末', 'meat', 50.0, 'g', '可选，铺在盘底', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '水', 'other', 500.0, 'ml', '用于炖煮', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '新鲜吐司', 'staple', 2.0, 'g', '建议选择厚度适中的切片吐司', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '果酱', 'sauce', 2.0, '汤匙', '可根据个人口味选择草莓、蓝莓等果酱', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '鸡蛋', 'egg_dairy', 1.0, '个', '选择新鲜的鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '盐', 'seasoning', 1.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '油', 'oil', 5.0, '毫升', '使用植物油或橄榄油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '新鲜鸡蛋', 'egg_dairy', 1.0, 'g', '推荐AA级', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '沸水', 'other', 1500.0, 'ml', '用于A锅', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '温水', 'other', 1500.0, 'ml', '用于B锅，保持在30°C', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '冰水', 'other', NULL, '足够覆盖鸡蛋', '用于终止加热', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '鸡蛋', 'egg_dairy', 2.0, '个', '新鲜鸡蛋为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '饮用水', 'other', 35.0, 'ml', '常温水', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '芝麻油', 'oil', 3.0, 'ml', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '盐', 'seasoning', 0.8, 'g', '调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '鸡蛋', 'egg_dairy', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '温水或高汤', 'other', 100.0, 'ml', '蛋液体积的1.0–1.2倍，水温40–50℃', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '食盐', 'seasoning', 1.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '生抽', 'sauce', 2.0, 'ml', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '香油', 'oil', NULL, '适量（几滴）', '出锅淋入', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '葱花', 'vegetable', NULL, '少许', '装饰，可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '黄油', 'oil', 30.0, 'g', '室温软化或切成小块', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '鸡蛋', 'egg_dairy', 1.0, '个', '中等大小', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '面粉', 'staple', 15.0, 'g', '普通面粉即可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '泡打粉', 'dry_goods', 2.5, 'g', '无铝泡打粉更健康', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '白（红）糖', 'seasoning', 10.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '盐', 'seasoning', 1.0, 'g', '一小撮', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '可选口味食材', 'other', NULL, '适量', '如巧克力、香蕉、坚果、饼干屑等', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '普通面粉', 'staple', 200.0, '克', '中筋面粉最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '开水', 'other', 100.0, '毫升', '刚烧开的水', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '冷水', 'other', 50.0, '毫升', '常温水', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '食用油', 'oil', 15.0, '毫升', '无味植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '盐', 'seasoning', 3.0, '克', '细盐', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '鸡蛋', 'egg_dairy', 1.0, '个', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '生菜', 'vegetable', 30.0, '克', '洗净沥干水分', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '火腿', 'meat', 30.0, '克', '切片备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '芝士片', NULL, 1.0, '片', '可根据喜好选择', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '糯米（或大米）', 'staple', 100.0, 'g', '如果使用大米，用量同样为100g', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '红枣', 'fruit', 15.0, '颗', '选择肉厚、色泽鲜红的红枣', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '桂圆', 'fruit', 15.0, '颗', '选择新鲜或干制的桂圆均可', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '新鲜玉米', 'staple', 1.0, '个', '选择颗粒饱满、色泽鲜艳的玉米', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '水', 'other', 300.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '盐', 'seasoning', 5.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '糖', 'seasoning', 5.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', '鸡蛋', 'egg_dairy', 2.0, '颗', '选择新鲜的鸡蛋，确保蛋壳完整无裂痕', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '速冻水饺', 'other', 15.0, '个', '选择自己喜欢的口味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '食用油', 'oil', 10.0, 'ml', '建议使用植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '清水', 'other', 150.0, 'ml', '根据锅具大小调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '黑芝麻', 'nut', NULL, '适量', '可选，增加香气', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '葱花', 'vegetable', NULL, '适量', '切段，增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '鸡蛋', 'egg_dairy', 2.0, '个', '新鲜鸡蛋最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '纯干燕麦片', 'staple', 50.0, 'g', '选择无糖无添加的燕麦片', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '牛奶', 'egg_dairy', 100.0, 'ml', '全脂或低脂均可，根据个人喜好调整', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '蔬菜碎叶', 'vegetable', 50.0, 'g（可选）', '如菠菜，洗净切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '黄油', 'oil', NULL, '适量', '用于煎饼，也可用植物油代替', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '牛奶', 'egg_dairy', 280.0, 'ml', '巴氏奶口感更好', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '燕麦', 'staple', 40.0, 'g', '快煮燕麦更方便', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '鸡蛋', 'egg_dairy', 1.0, '个', '新鲜鸡蛋最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', '全麦面包片', 'staple', 2.0, 'g', '建议使用粗粮面包片', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '鸡蛋', 'egg_dairy', 3.0, '个', '新鲜鸡蛋最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '全脂牛奶/奶油', 'egg_dairy', 10.0, '克（约1汤匙）', '使用全脂牛奶或淡奶油均可', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '黄油', 'oil', 5.0, '克（约半汤匙）', '无盐黄油更佳', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '盐', 'seasoning', 1.0, '克（约1/4茶匙）', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '鸡蛋', 'egg_dairy', 400.0, 'g（约8颗）', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '八角', 'spice', 4.0, 'g（约2颗）', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '香叶', 'spice', 0.5, '片', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '桂皮', 'spice', 3.0, 'g（1小块）', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '茴香', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '冰糖', 'seasoning', 15.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '红茶', 'other', 20.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '生抽', 'sauce', 15.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '老抽', 'sauce', 25.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '食盐', 'seasoning', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '新鲜鸡蛋', 'egg_dairy', 2.0, '个', '选择新鲜的鸡蛋，蛋黄饱满', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '热水', 'other', 260.0, 'ml', '温水温度在20-30℃之间', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '盐', 'seasoning', 2.0, 'g', '根据个人口味可适量调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '锡纸或保鲜膜', 'other', NULL, '适量', '用于覆盖碗口', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '中筋面粉', 'staple', 300.0, '克', '选择新鲜的面粉', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '温水', 'other', 150.0, '毫升', '约40°C左右', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '酵母', 'other', 3.0, '克', '活性干酵母', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '白糖', 'seasoning', 10.0, '克', '帮助发酵', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '食用油', 'oil', NULL, '适量', '防止粘连', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '糍粑', 'staple', 200.0, 'g（约两块）', '选择新鲜或冷冻的糍粑，如果是冷冻的需提前解冻', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '鸡蛋', 'egg_dairy', 1.0, '个', '中等大小的鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '红糖', 'other', 8.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '食用油', 'oil', 10.0, 'ml', '建议使用植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '食用盐', 'seasoning', 2.0, 'g', '可选，用于提味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '水浸金枪鱼罐头', 'seafood', 65.0, 'g', '不建议用油浸，会很腻', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '方形吐司片', 'staple', 2.0, '片', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '蛋黄酱', 'sauce', 50.0, 'mL', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '俄式酸黄瓜汁', 'sauce', 10.0, 'ml', '可根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '芝士片', NULL, 1.0, '片（可选）', '', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '火腿片', 'meat', 1.0, '片（可选）', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '鸡蛋', 'egg_dairy', 1.0, '个', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '吐司', 'staple', 2.0, '片', '全麦或白吐司', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '培根', 'meat', 2.0, '片', '选择烟熏风味更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '黄油', 'oil', 10.0, 'g', '无盐黄油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '蛋黄酱', 'sauce', 20.0, 'g', '可根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '盐', 'seasoning', 1.0, '/4小勺', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '黑胡椒', 'spice', NULL, '少许', '现磨黑胡椒最佳', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '面粉', 'staple', 77.0, 'g', '中筋面粉', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '食用油', 'oil', 100.0, 'ml', '建议使用花生油或菜籽油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '盐', 'seasoning', 5.0, 'g', '根据个人口味可适量调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '干辣椒面（粗细都准备）', 'spice', 60.0, '克', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '孜然粉', 'spice', 20.0, '克', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '胡椒粉', 'spice', 10.0, '克', '提味增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '五香粉', 'spice', 15.0, '克', '增加复合香味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '食盐', 'seasoning', 20.0, '克', '调味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '花椒粉', 'spice', 15.0, '克', '增加麻味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '鸡精', 'seasoning', 8.0, '克', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '十三香', 'spice', 5.0, '克', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '麻辣鲜', 'spice', 5.0, '克', '增加麻辣味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '白芝麻', 'nut', 30.0, '克', '增加香气和口感', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '食用油', 'oil', 200.0, 'ml', '用于热油浇制', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '香油', 'oil', 10.0, '毫升', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '生抽', 'sauce', 10.0, '毫升', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '花椒油', 'oil', 10.0, '毫升', '增加麻味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '蚝油', 'sauce', 10.0, '毫升', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '冰糖', 'seasoning', 200.0, 'g', '建议使用大块冰糖，提前敲碎成小块', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '油', 'oil', 100.0, 'ml', '植物油或花生油均可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '开水', 'other', 500.0, 'ml', '用于降温', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '清水', 'other', 50.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '生抽', 'sauce', 40.0, 'ml', '选择品质较好的生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '白糖', 'seasoning', 30.0, 'g', '根据个人口味可适当调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '白醋', 'seasoning', 20.0, 'ml', '也可以用米醋代替，但风味略有不同', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '料酒', 'seasoning', 10.0, 'ml', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '油', 'oil', 200.0, 'g', '建议使用花生油或菜籽油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '大葱/小葱', 'vegetable', 80.0, 'g', '选择新鲜、无黄叶的大葱或小葱', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '姜', 'spice', 20.0, 'g', '选择新鲜、无霉变的生姜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '洋葱', 'vegetable', 150.0, 'g', '选择新鲜、无腐烂的洋葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '料酒', 'seasoning', 10.0, 'ml', '用于去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '香菜', 'vegetable', NULL, '适量（可选）', '增加香气，可按个人喜好添加', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '开洋', 'seafood', 50.0, 'g', '提升鲜香和甜味，可选', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '蒜头', 'vegetable', 2.0, '瓣', '选择新鲜饱满的大蒜', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '白芝麻', 'nut', 5.0, '克', '建议使用炒香的白芝麻', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '花生油', 'oil', 15.0, '毫升', '可选用其他植物油代替', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '酱油', 'sauce', 30.0, '毫升', '推荐使用生抽，色泽更佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '蘸料碟', 'other', 1.0, '个', '确保干净无水', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '甘露咖啡酒', 'other', 10.0, 'ml', '选择品质好的甘露咖啡酒', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '爱尔兰百利甜酒', 'other', 10.0, 'ml', '选择正宗的爱尔兰百利甜酒', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '蓝天原味伏特加', 'other', 10.0, 'ml', '选择高纯度的伏特加', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '吧勺', 'other', 1.0, '个', '用于缓慢倒入酒精', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '利口酒杯', 'other', 1.0, '个', '确保杯子干净无水渍', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', '打火机', 'other', 1.0, '个', '用于点燃酒精', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '青柠', 'fruit', 1.0, '个', '选择新鲜、表皮光滑的青柠', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '薄荷叶', 'vegetable', 8.0, '片', '选择新鲜、叶片完整的薄荷叶', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '糖浆', 'other', 20.0, 'ml', '可以使用自制或市售的简单糖浆', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '白朗姆酒', 'other', 45.0, 'ml', '选择品质较好的白朗姆酒', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '冰镇苏打水', 'other', NULL, '适量', '确保苏打水是冰镇的', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', '碎冰', 'other', NULL, '适量', '提前准备好足够的碎冰', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '冬瓜', 'vegetable', 1000.0, 'g', '选择新鲜、皮薄肉厚的冬瓜', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '冰糖', 'seasoning', 300.0, 'g', '根据个人口味可适当增减', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '波旁威士忌', 'other', 100.0, '毫升', '选择品质较好的波旁威士忌', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '可口可乐', 'other', 500.0, '毫升', '冰镇过的可乐更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '冰块', 'other', 300.0, '克', '使用大块冰块可以减缓融化速度', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '柠檬', 'fruit', 1.0, '个', '新鲜柠檬，去籽切片', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '袋泡红茶', 'other', 2.0, 'g', '推荐使用立顿黄牌精选红茶', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '全脂奶粉或淡奶', 'egg_dairy', 11.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '砂糖', NULL, 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '奇亚籽', 'other', 24.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '牛奶', 'egg_dairy', 50.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '冰块', 'other', 2.0, '小块', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '芒果', 'fruit', 1.0, 'g', '选择成熟度高的芒果', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '葡萄柚', 'fruit', 1.0, 'g', '选择新鲜多汁的葡萄柚', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '椰奶', 'egg_dairy', 150.0, 'ml', '选择无糖椰奶', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '切丝芒果干', 'fruit', NULL, '适量', '可选，用于点缀', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '切丝柳橙干', 'fruit', NULL, '适量', '可选，用于点缀', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '酸梅晶固体饮料', 'other', 120.0, '克', '推荐使用品牌：康师傅或其他知名品牌', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '饮用水', 'other', 1177.0, '毫升', '建议使用纯净水或过滤水', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '方糖', NULL, 9.0, '克', '可根据个人口味调整，也可用白糖代替', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '北京二锅头酒', 'other', 48.0, '毫升', '可选，用于增加风味，不饮酒者可省略', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '金酒', 'other', 15.0, 'ml', '选择品质较好的金酒', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '龙舌兰酒', 'other', 15.0, 'ml', '选择银色或金色龙舌兰酒', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '伏特加', 'other', 15.0, 'ml', '选择无味或淡味伏特加', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '白朗姆酒', 'other', 15.0, 'ml', '选择白色朗姆酒', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '橙味甜酒', 'other', 15.0, 'ml', '如君度橙酒', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '柠檬', 'fruit', 1.0, '个', '新鲜柠檬，用于挤汁', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '枫糖浆', NULL, 20.0, 'ml', '可选，用于调整甜度', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '可乐', 'other', 75.0, 'ml', '冷藏过的可乐更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '冰块', 'other', 100.0, '克', '大块冰块，保持饮品冷度', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '鸭肉', 'meat', 1.0, 'kg', '让市场老板剁成小块', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '啤酒', 'other', 1000.0, 'ml', '可以买500 ml的罐装啤酒两瓶', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '青椒', 'vegetable', 2.0, '条', '长度10厘米到15厘米之间都可以，切段或切片都可以，2厘米一段', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '红椒', 'vegetable', 1.0, '条', '长度10厘米到15厘米之间都可以，切段或切片都可以，2厘米一段', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '大蒜', 'vegetable', 4.0, '颗', '拍散备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '生姜', 'vegetable', 3.0, '厘米长', '拍散备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '小米辣', 'vegetable', 3.0, '颗', '切两段即可,不吃辣的可以不用', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '蒜苗', 'vegetable', 2.0, '根', '切段备用', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '大葱', 'vegetable', 2.0, '根', '1根切段,1根备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '草果', 'spice', 2.0, '颗', '拍散去仔备用', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '桂皮', 'spice', 4.0, '厘米一小片', NULL, '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '八角', 'spice', 3.0, '颗', NULL, '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '香叶', 'spice', 3.0, '片', NULL, '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '干辣椒', 'spice', 6.0, '条', '不吃辣可以不用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '花椒', 'spice', 30.0, '颗', NULL, '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '料酒', 'seasoning', 20.0, 'ml', NULL, '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '花生油', 'oil', 60.0, 'ml', NULL, '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '盐', 'seasoning', 3.0, '克', NULL, '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '生抽', 'sauce', 10.0, 'ml', NULL, '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '老抽', 'sauce', 5.0, 'ml', NULL, '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '兔肉', 'meat', 500.0, '克', '新鲜兔肉，去骨切块', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '盐', 'seasoning', 1.0, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '味精', 'seasoning', 0.5, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '蚝油', 'sauce', 2.5, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '料酒', 'seasoning', 5.0, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '蒜', 'vegetable', NULL, '半个头', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '姜', 'spice', NULL, '半个头', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '小葱/大葱/洋葱', 'vegetable', 7.5, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '干辣椒', 'spice', 500.0, 'g', '辣椒段的总体积等于兔肉的总体积', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '青花椒', 'spice', NULL, '适量', '3斤兔肉对应一小碗', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '八角', 'spice', 1.0, '粒', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '桂皮', 'spice', NULL, '大拇指长短的一块', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '香叶', 'spice', 5.0, '片', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '山奈', 'spice', NULL, '黄豆大小的一块', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '白蔻', 'spice', 2.0, '颗', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '小茴香', 'spice', 7.5, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '白芝麻', 'nut', 12.5, '克', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '食用油', 'oil', 450.0, '毫升', '根据兔肉重量计算', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '鸡翅中', 'meat', 10.0, '只', '选择新鲜的鸡翅', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '可乐', 'other', 500.0, 'ml', '普通可乐即可', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '白糖', 'seasoning', 10.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '生抽', 'sauce', 15.0, '克', '用于腌制和调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '老抽', 'sauce', 3.0, '克', '用于调色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '盐', 'seasoning', 2.0, '克', '适量调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '生姜', 'vegetable', 2.0, '片', '切片备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '料酒', 'seasoning', 20.0, '毫升', '可用啤酒代替', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '小葱', 'vegetable', 1.0, '根', '挽成结', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '梅头猪肉', 'meat', 300.0, 'g', '选择带点肥肉的部分，口感更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '青椒', 'vegetable', 75.0, 'g', '选择颜色鲜艳、质地脆嫩的青椒', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '罐头菠萝片', 'fruit', 225.0, 'g', '也可以用新鲜菠萝切片代替', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '盐', 'seasoning', 1.0, '/2茶匙', '腌制用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '茄汁', 'sauce', 12.0, '汤匙', '约180ml', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '白醋', 'seasoning', 6.0, '茶匙', '约30ml', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '蒜蓉', 'vegetable', 3.0, '汤匙', '约45g', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '生抽', 'sauce', 1.5, '茶匙', '约7.5ml', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '生粉', 'staple', 7.5, '汤匙', '约112.5g，其中6汤匙用于裹肉，1.5汤匙用于酱汁', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '白砂糖', 'seasoning', 6.0, '汤匙', '约90g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '水', 'other', 600.0, '毫升', '用于调制酱汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '带皮猪五花肉（去骨）', 'meat', 500.0, '克', '选择肥瘦相间的五花肉', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '商芝（又名紫萁，属蕨类，嫩叶可食）', 'vegetable', 50.0, '克', '若无商芝，可用其他蕨类蔬菜代替', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '葱', 'vegetable', 10.0, '克', '切段和斜片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '姜', 'spice', 2.0, '克', '切片和末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '八角', 'spice', 3.0, '个', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '蜂蜜', 'other', 15.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '醋', 'seasoning', 5.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '料酒', 'seasoning', 15.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '味精', 'seasoning', 1.5, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '酱油', 'sauce', 10.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '摊制的鸡蛋皮', 'egg_dairy', 15.0, 'g', '切成2.4cm长的等腰三角形片', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '精盐', 'seasoning', 1.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '鸡汤', 'other', 200.0, '克', '分两次使用，每次100克', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '芝麻油', 'oil', 10.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '熟猪油', 'oil', 2000.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '牛柳或牛肩肉', 'meat', 500.0, 'g', '选择新鲜、有弹性的牛肉', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '青椒', 'vegetable', 4.0, 'g', '选择颜色鲜艳、质地脆嫩的青椒', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '孜然（颗粒>粉）', 'spice', 40.0, 'g', '尽量选择颗粒状孜然，香气更浓郁', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '小米椒', 'spice', 6.0, 'g', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '生抽酱油', 'sauce', 40.0, 'ml', '选择品质好的生抽，味道更鲜美', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '淀粉', 'dry_goods', 20.0, 'g', '用于腌制牛肉，使其更加嫩滑', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '油', 'oil', 30.0, 'ml', '建议使用花生油或调和油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '盐', 'seasoning', 6.0, 'g', '根据个人口味适量调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '葱', 'vegetable', 2.0, 'g', '选择新鲜、无烂叶的葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '五花肉', 'meat', 500.0, 'g', '选择肥瘦相间的五花肉', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '朝天椒', 'vegetable', 4.0, '条', '根据个人口味调整数量', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '小米椒', 'spice', 4.0, '颗', '根据个人口味调整数量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '豆豉', 'sauce', 10.0, 'g', '根据个人口味调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '豆瓣酱', 'sauce', 10.0, 'g', '根据个人口味调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '老抽', 'sauce', 10.0, 'ml', '用于上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '淀粉', 'dry_goods', 10.0, 'g', '用于腌制肉片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '盐', 'seasoning', 1.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '葱', 'vegetable', 0.5, '根', '切段备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '蒜', 'vegetable', 2.0, '瓣', '切片备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '食用油', 'oil', 15.0, 'ml', '用于炒制', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '小米椒', 'spice', 20.0, '个（根据个人口味加减）', '选择新鲜、颜色鲜艳的小米椒', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '花生油', 'oil', 20.0, 'ml', '也可以用其他植物油代替', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '五花肉/瘦肉', 'meat', 200.0, 'g', '切成薄片或丝', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '盐', 'seasoning', 1.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '生抽', 'sauce', 10.0, 'ml', '用于腌制和调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '蚝油', 'sauce', 10.0, 'ml', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '大蒜', 'vegetable', 25.0, 'g', '切片或拍碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '姜', 'spice', 25.0, 'g', '切片或拍碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '豆瓣酱', 'sauce', 10.0, 'g', '根据个人口味加减', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '鸡精', 'seasoning', 1.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '白糖', 'seasoning', 5.0, 'g', '中和辣味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '去皮猪肉', 'meat', 500.0, 'g', '肥瘦适中，根据喜好选择', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '鸡蛋', 'egg_dairy', 2.0, '个', '取蛋清用于裹粉，蛋黄可另用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '面粉', 'staple', 30.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '红薯淀粉', 'dry_goods', 120.0, 'g', '需提前过筛，避免结块', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '老姜', 'vegetable', 20.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '小葱', 'vegetable', 15.0, 'g', '不切，整段使用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '料酒', 'seasoning', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '清水', 'other', 80.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '盐', 'seasoning', 4.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '十三香', 'spice', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '胡椒粉', 'spice', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '味精', 'seasoning', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '鸡精', 'seasoning', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '花椒碎', 'spice', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '花椒粒', 'spice', 3.0, 'g', '可轻拍碎更出味', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '生抽', 'sauce', 8.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '植物油', 'oil', NULL, '适量', '用于炸制，初炸油量需没过肉条1/2，复炸需足量', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '牛肉（里脊或牛柳）', 'meat', 500.0, 'g', '选择肉质细嫩的部位', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '葱', 'vegetable', 1.0, '根', '约100g，切段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '姜', 'spice', 20.0, 'g', '切成片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '蒜', 'vegetable', 3.0, '瓣', '剁成蒜泥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '尖椒', 'vegetable', 2.0, '个', '约200g，切成段', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '酱油', 'sauce', 18.0, 'ml', '生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '盐', 'seasoning', 6.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '糖', 'seasoning', 3.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '小苏打', 'other', 3.0, 'g', '可选，用于嫩化牛肉', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '猪里脊', 'meat', 150.0, 'g', '选择新鲜的猪里脊肉', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '蒜苔', 'vegetable', 6.0, '根', '切段备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '盐', 'seasoning', 10.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '生抽', 'sauce', 20.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '葱姜蒜', 'vegetable', 50.0, 'g', '切末备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '鸡蛋', 'egg_dairy', 1.0, '个', '打散备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '淀粉', 'dry_goods', 10.0, 'g', '建议使用红薯淀粉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '食用油', 'oil', 300.0, 'ml', '炸肉片用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '木耳', 'mushroom', 20.0, 'g', '提前泡发好', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '葱头', 'vegetable', 100.0, 'g', '切菱形块备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '料酒', 'seasoning', 10.0, 'ml', '腌制用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '陈醋', 'sauce', 10.0, 'ml', '起锅前调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '花椒粉', 'spice', NULL, '适量', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '鸡精', 'seasoning', NULL, '适量', '起锅前调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '带脚、爪猪前肘', NULL, 1250.0, '克', '选择新鲜的猪前肘', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '红豆腐乳', 'sauce', 1.0, 'g', '选择品质好的红豆腐乳', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '甜面酱', 'sauce', 150.0, '克', '选择口感细腻的甜面酱', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '精盐', 'seasoning', 15.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '红酱油', 'sauce', 35.0, '克', '可选用老抽或特制红酱油', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '白酱油', 'sauce', 25.0, '克', '可选用生抽', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '料酒', 'seasoning', 25.0, '克', '去腥提香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '蒜片', 'vegetable', 50.0, '克', '切片备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '姜末', 'spice', 10.0, '克', '切末备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '八角', 'spice', 3.0, '个', '整颗使用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '桂皮', 'spice', 5.0, '克', '小块即可', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '葱', 'vegetable', 200.0, '克', '切段备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '鸡腿肉', 'meat', 4.0, 'g', '选择新鲜无异味的鸡腿', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '盐', 'seasoning', 4.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '黑胡椒', 'spice', 2.0, '克', '现磨黑胡椒更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '橄榄油', 'oil', 20.0, '毫升', '使用特级初榨橄榄油', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '蒜', 'vegetable', 4.0, '瓣', '切末或压成蒜泥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '柠檬汁', 'fruit', 20.0, '毫升', '新鲜挤出', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '欧芹', 'vegetable', 4.0, '根', '洗净后切碎', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '血肠', 'meat', 200.0, '克', '选择新鲜的血肠', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '酸菜', 'vegetable', 500.0, '克', '选择腌制好的酸菜', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '排骨', 'meat', 400.0, '克', '选择带肉的排骨', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '料酒', 'seasoning', 10.0, '克', '用于去腥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '蒜瓣', 'vegetable', 5.0, '个', '切片备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '姜粉', 'spice', 5.0, '克', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '干辣椒', 'spice', 5.0, '个', '根据口味调整数量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '香叶', 'spice', 2.0, '片', '增香', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '八角', 'spice', 1.0, '个', '增香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '葱结', 'vegetable', 1.0, '个', '打结备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '香油', 'oil', 10.0, '克', '提香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '菜籽油', 'oil', 10.0, '克', '炒菜用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '盐', 'seasoning', 5.0, '克', '调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '枸杞', 'fruit', NULL, '适量', '点缀用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '蘸料', 'sauce', NULL, '适量', '辣椒油 5 克、生抽 10 克、蒜蓉 5 克、香油 2 克', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '大排', 'meat', 4.0, 'g', '选择肉质鲜嫩的大排', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '鸡蛋', 'egg_dairy', 1.0, 'g', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '盐', 'seasoning', 1.0, '克', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '椒盐粉', 'seasoning', 10.0, '克', '用于腌制和撒料', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '葱姜水', 'seasoning', 100.0, '毫升', '葱姜切片后加水浸泡', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '面粉', 'staple', 80.0, '克', '普通面粉', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '淀粉', 'dry_goods', 80.0, '克', '玉米淀粉或土豆淀粉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '吉士粉', 'dry_goods', 2.0, '克', '增色增香，没有可以不放', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '水', 'other', 10.0, '克', '调糊用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '油', 'oil', NULL, '适量', '炸制用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '猪里脊肉', 'meat', 300.0, 'g', '需切2毫米薄片，提前清洗去血水并挤干', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '绿豆芽', 'vegetable', 100.0, 'g', '垫底蔬菜之一', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '凤尾', 'vegetable', 1.0, '根', '原文未明确品种，按上下文推测为绿叶蔬菜类（如凤尾菇或油麦菜），改刀成小条', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '芹菜', 'vegetable', 3.0, '根', '切小段', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '蒜苗', 'vegetable', 2.0, '根', '拍散后切小段', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '大蒜', 'vegetable', 20.0, 'g', '剁碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '生姜', 'vegetable', 10.0, 'g', '剁碎', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '红泡椒', 'vegetable', 20.0, 'g', '剁碎；辣度可调范围0–40g', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '小米辣干辣椒', 'spice', 20.0, 'g', '即干辣椒段，辣度可调范围0–40g', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '青花椒', 'spice', 5.0, 'g', '麻度可调，建议起始量3g，可增至10g', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '红油豆瓣酱', 'sauce', 10.0, 'g', '操作中实际用量；原文‘计算’部分写5ml，以操作为准', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '小葱', 'vegetable', 2.0, '根', '切葱花，用于泼油前撒面及装饰', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '鸡蛋清', 'egg_dairy', 1.0, '个', '用于腌肉增嫩', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '土豆淀粉', 'dry_goods', 7.0, 'g', '与蛋清调匀后腌肉', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '食用盐', 'seasoning', 5.0, 'g', '分次使用：腌肉1.5g、炒配菜1g、汤底2.5g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '胡椒粉', 'spice', 2.0, 'g', '分次使用：腌肉1g、汤底1g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '生抽酱油', 'sauce', 5.0, 'g', '用于腌肉', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '料酒', 'seasoning', 3.0, 'g', '用于腌肉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '鸡精', 'seasoning', 1.5, 'g', '加入汤底提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '白砂糖', 'seasoning', 1.0, 'g', '汤底提鲜用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '植物油', 'oil', 280.0, 'g', '分三次使用：腌肉30g、炒配菜100g、炒豆瓣150g', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '菜籽油', 'oil', 200.0, 'g', '专用于最后高温泼油，不可省略；与植物油分开计算', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '洋葱', 'vegetable', 200.0, 'g', '选择新鲜、紧实的洋葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '猪肉片', 'meat', 250.0, 'g', '猪肩肉片或切好的肉丝均可', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '蒜头', 'vegetable', 3.0, '瓣', '拍碎备用', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '食用油', 'oil', 15.0, 'ml', '用于炒制', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '黑胡椒', 'spice', 1.25, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '酱油', 'sauce', 30.0, 'ml', '生抽或老抽均可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '糖', 'seasoning', 15.0, 'g', '提鲜增甜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '麻油', 'oil', 5.0, 'ml', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '番茄酱', 'sauce', 15.0, 'ml', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '料酒', 'seasoning', 15.0, 'ml', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '鸡翅中', 'meat', 6.0, '个', '选择新鲜、肉质饱满的鸡翅', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '盐', 'seasoning', 4.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '黑胡椒粉', 'spice', 2.0, '克', '现磨更佳', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '酱油', 'sauce', 6.0, '毫升', '生抽或老抽均可，根据喜好选择', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '料酒', 'seasoning', 6.0, '毫升', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '蜂蜜', 'other', 1.0, 'ml', '增加光泽和甜味', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '姜蒜粉', 'spice', 1.0, 'g', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '五香粉', 'spice', 1.0, 'g', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '猪五花肉或排骨', 'meat', 1500.0, '克', '选择带皮五花肉或排骨，口感更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '东北酸菜', 'vegetable', 1000.0, '克', '选择新鲜、无异味的酸菜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '大葱', 'vegetable', 1.0, '根', '选择粗壮的大葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '姜', 'spice', 100.0, '克', '50克切段，50克切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '蒜', 'vegetable', 4.0, '瓣', '切末备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '盐', 'seasoning', 10.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '生抽酱油', 'sauce', 15.0, '克', '约1汤匙', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '五香粉', 'spice', 10.0, '克', '约1茶匙', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '料酒', 'seasoning', 20.0, '毫升', '约1.5汤匙', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '大料', 'spice', 2.0, '颗', '八角', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '鸡全翅', 'meat', 4.0, '个', '含翅尖、翅中、翅根', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '生抽', 'sauce', 45.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '老抽', 'sauce', 15.0, 'ml', '用于上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '蒜粉', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '胡椒粉', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '糖', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '甜椒粉', 'spice', 10.0, 'g', '增色增香，非辣味来源', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '辣椒粉', 'spice', 5.0, 'g', '微辣口感；如需更辣可增至最多30g', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '蚝油', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '水', 'other', 20.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '油', 'oil', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '碎牛肉', 'meat', 500.0, 'g', '也可以用一半碎猪肉一半碎牛肉', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '蒜瓣', 'vegetable', 2.0, '个', '切片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '胡萝卜', 'vegetable', NULL, '半根', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '芹菜', 'vegetable', NULL, '一根', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '洋葱', 'vegetable', NULL, '半个', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '橄榄油', 'oil', 20.0, 'ml', '分两次使用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '糖', 'seasoning', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '食盐', 'seasoning', 10.0, 'g', '根据番茄酱咸度调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '黑胡椒粉', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '番茄酱', 'sauce', 300.0, 'g', '选择品质好的番茄酱', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '牛奶', 'egg_dairy', 300.0, 'ml', '可以用鸡汤或饮用水代替', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '干罗勒或百里香', 'spice', NULL, '适量', '可选', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '五花肉', 'meat', 300.0, 'g', '选择肥瘦相间的五花肉', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '大白菜', 'vegetable', 500.0, 'g', '新鲜的大白菜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '土豆干粉条', 'staple', 50.0, 'g', '提前浸泡至软', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '十三香', 'spice', 1.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '鸡精', 'seasoning', 1.0, 'g', '提鲜用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '食用盐', 'seasoning', 1.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '老抽', 'sauce', 1.0, 'ml', '上色用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '生抽', 'sauce', 1.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '食用油', 'oil', 10.0, 'ml', '炒菜用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '五花肉', 'meat', 500.0, 'g', '肥瘦相间', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '蒸肉米粉', 'staple', 100.0, 'g', '推荐李锦记或自制', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '生抽', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '老抽', 'sauce', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '料酒', 'seasoning', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '郫县豆瓣酱', 'sauce', 10.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '姜末', 'spice', 10.0, 'g', '颗粒直径≤1mm', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '蒜末', 'seasoning', 10.0, 'g', '颗粒直径≤1mm', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '白砂糖', 'seasoning', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '土豆', 'vegetable', 300.0, 'g', '或南瓜300g，作为垫底食材', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '清水', 'other', 2000.0, 'ml', '蒸锅用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '里脊肉', 'meat', 500.0, 'g', '选择新鲜的猪里脊肉', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '醋', 'seasoning', 10.0, 'g', '使用米醋或陈醋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '白糖', 'seasoning', 30.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '淀粉', 'dry_goods', 50.0, 'g', '用于裹粉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '鸡蛋', 'egg_dairy', 1.0, 'g', '用于腌制', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '生抽', 'sauce', 10.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '料酒', 'seasoning', 20.0, 'g', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '蚝油', 'sauce', 10.0, 'g', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '番茄酱', 'sauce', 30.0, 'ml', '调色和增加酸甜味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '白胡椒粉', 'spice', 5.0, 'g', '提味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '食盐', 'seasoning', 10.0, 'g', '调味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '猪肉末', 'meat', 300.0, 'g', '选择肥瘦相间的猪肉末，口感更佳', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '鸡蛋', 'egg_dairy', 2.0, '个', '新鲜的鸡蛋味道更好', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '料酒', 'seasoning', 10.0, 'ml', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '生抽', 'sauce', 20.0, 'ml', '调味提色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '白胡椒粉', 'spice', 5.0, 'g', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '芝麻香油', 'oil', 10.0, 'ml', '提升香气', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '带皮五花肉', 'meat', 400.0, 'g', '选择肥瘦相间的五花肉', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '红腐乳', 'tofu', 30.0, '块', '推荐咸亨牌玫瑰腐乳', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '腐乳汁', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '冰糖', 'seasoning', 25.0, 'g', '建议使用单晶冰糖', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '老抽', 'sauce', 5.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '料酒', 'seasoning', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '葱白', 'vegetable', 15.0, 'g', '切段', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '葱花', 'vegetable', 5.0, 'g', '切碎，用于最后撒在上面', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '生姜', 'vegetable', 10.0, 'g', '切片', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '清水', 'other', 500.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '食用油', 'oil', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '羊排', 'meat', 400.0, 'g', '购买时让卖家切好', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '白萝卜', 'vegetable', 1.0, 'g', '选择新鲜、无斑点的白萝卜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '大葱', 'vegetable', 1.0, '根', '选用粗壮的大葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '花椒', 'spice', 10.0, '粒', '根据个人口味可适量增减', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '白芷', 'spice', 1.0, '片（可选）', '增加香气，可选', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '姜', 'spice', 10.0, '片', '去皮切片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '料酒或黄酒', 'seasoning', 30.0, 'ml', '去腥提香', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '食用盐', 'seasoning', 10.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '冰糖', 'seasoning', 2.0, '粒', '增加汤的甜味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '水', 'other', 1300.0, 'ml', '没过食材', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '蒜苔', 'vegetable', 190.0, 'g', '1扎', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '五花肉', 'meat', 20.0, 'g', '切丝，原为薄片', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '食用油', 'oil', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '生抽', 'sauce', 15.0, 'ml', '分两次使用：5ml用于炒肉，10ml用于炒蒜苔', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '食盐', 'seasoning', 2.0, 'g', '最后加入，可依口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '蒜瓣', 'vegetable', 2.0, '个', '拍碎切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '猪前肘', 'meat', 1.0, 'g', '选择新鲜、无异味的猪前肘', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '食用植物油', 'oil', NULL, '适量', '用于油炸，约1L', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '冰糖', 'seasoning', 30.0, 'g', '用于炒糖色', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '盐', 'seasoning', 1.0, '茶匙', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '老抽', 'sauce', 1.0, '汤匙', '调色调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '生抽', 'sauce', 1.0, '汤匙', '调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '白醋', 'seasoning', 1.0, '汤匙', '去腥提香', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '香叶', 'spice', 3.0, '片', '增香', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '肉桂皮', 'spice', 2.0, '克', '增香', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '豆蔻', 'spice', 3.0, '个', '增香', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '花椒', 'spice', 8.0, '粒', '增香', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '大料', 'spice', 2.0, '个', '增香', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '淀粉', 'dry_goods', 1.0, '汤匙', '勾芡用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '葱', 'vegetable', 2.0, '棵', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '姜', 'spice', 6.0, '克', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '蒜', 'vegetable', 6.0, '粒', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '水', 'other', NULL, '适量', '用于炖煮', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '料酒', 'seasoning', 2.0, '汤匙', '去腥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '红薯粉丝', 'staple', 80.0, 'g', '干重，需提前泡发', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '猪肉末', 'meat', 150.0, 'g', '也可用牛肉末替代', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '郫县豆瓣酱', 'sauce', 15.0, 'g', '含盐量高，生抽需酌减', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '生抽', 'sauce', 10.0, 'ml', '根据豆瓣酱用量可调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '老抽', 'sauce', 5.0, 'ml', '用于上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '食用油', 'oil', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '蒜末', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '姜末', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '清水', 'other', 300.0, 'ml', '用于煮粉丝及炖煮汤汁', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '小葱', 'vegetable', NULL, '适量', '可选，出锅前撒入', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '肋排', 'meat', 500.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '阳江豆豉', 'sauce', 15.0, 'g', '浸泡5分钟后稍剁碎更入味', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '蒜蓉', 'vegetable', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '姜末', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '生抽', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '老抽', 'sauce', 3.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '蚝油', 'sauce', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '白砂糖', 'seasoning', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '生粉', 'staple', 8.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '食用油', 'oil', 20.0, 'ml', '其中10 ml用于腌制，10 ml用于最后淋热油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '清水', 'other', 30.0, 'ml', '用于豆豉浸泡及调汁（如需）', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '葱花', 'vegetable', NULL, '适量', '可选，最后撒用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '白芝麻', 'nut', NULL, '适量', '可选，最后撒用', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '青椒', 'vegetable', 3.0, '个', '推荐杭椒、螺丝椒（吃辣）或尖椒、甜椒（不吃辣）；螺丝椒为最优解；不可用其他辣椒品种', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '猪瘦肉', 'meat', 200.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '盐', 'seasoning', 3.0, 'g', '其中2g用于干煸青椒后加盐，1g用于腌肉（按总量分配推得）', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '生抽', 'sauce', 3.0, 'ml', '用于腌肉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '蚝油', 'sauce', 3.0, 'ml', '用于腌肉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '大蒜', 'vegetable', 5.0, 'g', '拍松后切蒜瓣', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '生姜', 'vegetable', 5.0, 'g', '切姜末', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '酱油', 'sauce', 2.0, 'ml', '可选，出锅前加入', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '豆豉', 'sauce', 3.0, 'g', '可选，按口味加入', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '猪里脊', 'meat', 200.0, 'g', '切成细丝', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '香干', 'tofu', 150.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '青椒', 'vegetable', 1.0, '个', '洗净后滚刀切丝', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '大蒜', 'vegetable', 10.0, '瓣', '横切成片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '盐', 'seasoning', 6.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '生抽', 'sauce', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '淀粉', 'dry_goods', 10.0, 'g', '与水混合勾芡用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '鸡精', 'seasoning', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '食用油', 'oil', 30.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '里脊肉', 'meat', 200.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '胡萝卜', 'vegetable', 100.0, 'g', '切丝，焯水', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '青椒', 'vegetable', 100.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '木耳（干）', 'mushroom', 5.0, 'g', '泡发4小时，洗净切小块', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '生抽', 'sauce', 10.0, 'ml', '分两次使用：腌料5ml、香汁5ml', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '料酒', 'seasoning', 5.0, 'ml', '全部用于腌料', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '蛋清', 'egg_dairy', 1.0, '个', '全部用于腌料', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '淀粉', 'dry_goods', 10.0, 'g', '分两次使用：腌料5g、香汁5g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '醋', 'seasoning', 15.0, 'ml', '全部用于香汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '白糖', 'seasoning', 10.0, 'g', '全部用于香汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '盐', 'seasoning', 5.0, 'g', '分两次使用：香汁1g，余量可能用于焯水或调味（未明确，按原文保留）', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '姜', 'spice', 20.0, 'g', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '葱', 'vegetable', 20.0, 'g', '切5mm小段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '蒜', 'vegetable', 2.0, '瓣', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '豆瓣酱', 'sauce', 15.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '水', 'other', 40.0, 'ml', '分两次使用：腌料20ml、香汁20ml，原文未列在必备原料中', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '食用油', 'oil', 20.0, 'ml', '分两次使用：滑肉15ml、爆香5ml', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '油菜', 'vegetable', 150.0, '克', '新鲜嫩绿', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '油麦菜', 'vegetable', 150.0, '克', '新鲜嫩绿', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '菠菜', 'vegetable', 155.0, '克', '新鲜嫩绿', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '猪肉', 'meat', 150.0, '克', '切片或切条', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '牛肉', 'meat', 100.0, '克', '切片或切条', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '鸡肉', 'meat', 100.0, '克', '切片或切条', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '鱼丸', 'seafood', 50.0, '克', '中等大小', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '火腿肠', 'meat', 30.0, '克', '切片', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '干豆腐', 'tofu', 152.0, '克', '切条', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '北京麻辣方便面', 'staple', 1.0, '袋', '约100克', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '干辣椒', 'spice', 5.0, '克', '根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '麻辣香锅调料', 'seasoning', 110.0, '克', '推荐品牌：海底捞、好人家等', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '食用油', 'oil', 105.0, '克', '花生油或植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '鸡腿', 'meat', 500.0, 'g', '选择新鲜的鸡腿', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '干香菇', 'mushroom', 5.0, '朵', '提前泡发，留香菇水备用', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '青椒', 'vegetable', NULL, '两个', '选择颜色鲜艳、肉质厚实的青椒', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '生姜', 'vegetable', NULL, '两片', '切片备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '干辣椒', 'spice', 5.0, '个', '根据口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '盐', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '料酒', 'seasoning', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '白胡椒粉', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '白糖', 'seasoning', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '酱油', 'sauce', 5.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '味精', 'seasoning', NULL, '适量', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '土豆', 'vegetable', 200.0, 'g', '可选，切为滚刀块', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '黄瓜', 'vegetable', 200.0, '克', '选择新鲜、硬实的黄瓜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '猪瘦肉', 'meat', 100.0, '克', '选择里脊肉或后腿肉，去筋膜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '食用油', 'oil', 50.0, '克', '分两次使用，腌制和炒制各用10克和40克', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '生抽', 'sauce', 1.0, 'g', '用于腌制猪肉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '盐', 'seasoning', 10.0, '克', '分两次使用，腌制黄瓜8克，炒制时2克', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '蒜', 'vegetable', 4.0, '瓣', '切成蒜末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '小米辣', 'vegetable', 2.0, '个', '去蒂切段', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '凉皮', 'staple', 600.0, 'g（约2-3人份）', '超市购买的凉皮表面一般会有食用油，可以使用自来水清洗', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '面筋', 'tofu', NULL, '适量', '清洗后挤出多余水分', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '盐', 'seasoning', 14.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '鸡精', 'seasoning', 5.0, 'g', '可根据个人喜好增减', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '蚝油', 'sauce', 4.0, 'g', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '生抽', 'sauce', 10.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '老抽', 'sauce', 2.0, 'g', '上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '香油', 'oil', 1.0, 'g', '增香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '香醋', 'sauce', 10.0, 'g', '提酸', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '芝麻酱', 'sauce', 60.0, 'g（约2-3人份）', '原味芝麻酱最佳', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '黄瓜', 'vegetable', 200.0, 'g（约2-3人份）', '切丝备用', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '绿豆芽', 'vegetable', 100.0, 'g（约2-3人份）', '焯水后过凉水备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '大蒜', 'vegetable', 20.0, '瓣', '剥皮后捣成蒜泥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '半成品意大利面', 'staple', 520.0, 'g（推荐品牌圃美多）', '确保包装上注明可直接加热', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '清水', 'other', 50.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '酱料', 'sauce', NULL, '随面条附带的酱料包', '根据个人口味选择不同风味', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '牛油', 'oil', 4500.0, 'g', '选用新鲜无异味的牛油', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '色拉油或菜籽油', 'oil', 1000.0, 'ml', '根据个人喜好选择', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '纯猪油', 'oil', 500.0, 'g', '增加香味', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '豆瓣（郫县）', 'sauce', 1000.0, 'g', '选用红油豆瓣酱', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '糍粑辣椒', 'spice', 3000.0, 'g', '提前泡软', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '老姜（切片）', 'vegetable', 250.0, 'g', '去皮切片', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '大葱（切段）', 'vegetable', 100.0, 'g', '洗净切段', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '洋葱（切丝）', 'vegetable', 100.0, 'g', '切细丝', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '大蒜（切片）', 'vegetable', 200.0, 'g', '去皮切片', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '豆鼓（剁碎）（永川）', 'sauce', 10.0, 'g', '剁碎备用', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '豆母子', 'other', 140.0, 'g', '即黄豆酱，增加风味', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '红花椒', 'spice', 150.0, 'g', '选颗粒饱满的', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '颗粒香料', 'spice', 100.0, 'g', '见下文香料列表', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '整形香料', 'spice', 150.0, 'g', '见下文香料列表', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '麦芽粉（肉香）', 'other', 12.5, 'g', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '白酒(52%VOL)', 'other', 150.0, 'ml', '高度白酒去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '干辣椒面', 'spice', 15.0, 'g', '用于制作老油', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '速冻水饺', 'other', 7.0, '个', '选择未过期的品牌', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '水', 'other', NULL, '适量', '饺子高度的1-2倍', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '黑醋', 'sauce', 10.0, 'ml', '可选，用于蘸料', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '姜', 'spice', 50.0, 'g', '可选，切丝用于蘸料', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '香油', 'oil', 2.0, '滴', '可选，用于蘸料', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '大蒜/蒜泥', 'vegetable', 3.0, '瓣/人', '可选，用于蘸料', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '速冻馄饨', 'staple', 12.0, '个', '选择未过期的产品', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '水', 'other', 600.0, 'ml', '根据馄饨数量调整水量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '盐', 'seasoning', 1.0, 'g', '仅在无调味料包时使用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '鸡精', 'seasoning', 1.0, 'g', '仅在无调味料包时使用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '胡椒粉', 'spice', 1.0, 'g', '仅在无调味料包时使用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '香油', 'oil', 1.0, 'ml', '仅在无调味料包时使用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '香菜', 'vegetable', 1.0, '根', '可选，切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '白蘑菇', 'mushroom', 200.0, 'g', '切片', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '洋葱', 'vegetable', 50.0, 'g', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '黄油', 'oil', 15.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '面粉', 'staple', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '牛奶', 'egg_dairy', 200.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '淡奶油', 'egg_dairy', 30.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '清水', 'other', 100.0, 'ml', '可用鸡高汤替代，总液体不超过300 ml/份', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '盐', 'seasoning', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '黑胡椒碎', 'spice', 1.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '小米', 'staple', 100.0, '克', '选择新鲜的小米，颜色金黄，无杂质', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '水（山泉水最佳）', 'other', 2000.0, '克', '使用纯净水或过滤水也可以', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '前腿肉', 'meat', 300.0, 'g', '肥瘦三七分', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '盐', 'seasoning', 18.0, 'g', '每斤肉6克盐', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '胡椒粉', 'spice', 6.0, 'g', '每斤肉2克胡椒粉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '葱姜花椒水', 'other', 240.0, 'ml', '每斤肉80ml', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '鸡蛋清', 'egg_dairy', 1.0, '个', '只用蛋清', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '土豆淀粉', 'dry_goods', 40.0, 'g', '一人用量', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '熟豆油', 'oil', 20.0, 'ml', '保持嫩滑弹的状态', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '木耳', 'mushroom', 10.0, 'g（干）', '泡发后约50g', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '黄花', 'dry_goods', 10.0, 'g（干）', '泡发后约50g', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '小香葱', 'vegetable', NULL, '适量', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '粉丝', 'staple', 50.0, 'g', '提前泡软', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '鸡粉', 'seasoning', NULL, '适量', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '香油', 'oil', 3.0, '滴', '提香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '香菜', 'vegetable', NULL, '适量', '装饰用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '牛肉', 'meat', 300.0, 'g', '选择瘦肉部分，切薄片', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '番茄', 'vegetable', 2.0, '个', '选择成熟度高的番茄，切小块', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '鸡蛋', 'egg_dairy', 2.0, '个', '打散备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '葱', 'vegetable', NULL, '适量', '切成葱花', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '姜', 'spice', NULL, '几片', '切成姜片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '蒜', 'vegetable', NULL, '几瓣', '剁成蒜泥', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '盐', 'seasoning', 4.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '胡椒粉', 'spice', 1.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '水', 'other', 1.5, 'L', '清水', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '饮用水', 'other', 1.0, '升', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '皮蛋（松花蛋）', 'egg_dairy', 2.0, '颗', '选择新鲜的皮蛋', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '瘦肉', 'meat', 100.0, '克', '选用猪里脊肉或瘦猪肉', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '大米', 'staple', 150.0, '毫升', '提前浸泡半小时', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '小葱', 'vegetable', 1.0, '棵', '洗净备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '香菜', 'vegetable', 1.0, '棵', '洗净备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '生菜', 'vegetable', 4.0, '叶', '洗净备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '生姜', 'vegetable', 1.0, '拇指块', '约10克', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '酱油', 'sauce', 5.0, '毫升', '生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '蚝油', 'sauce', 5.0, '毫升', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '盐', 'seasoning', 2.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '胡椒粉', 'spice', 1.0, '克', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '食用油', 'oil', 10.0, '毫升', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '大米', 'staple', 150.0, '克', '选择优质大米，淘洗干净', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '水', 'other', 1.35, '升', '根据个人喜好调整水量，喜欢稀一点可以多加水', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '植物油', 'oil', 15.0, '毫升（可选）', '用于增加米粥的香气', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '干紫菜', 'seafood', 10.0, 'g', '根据个人喜好可适量增减', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '鸡蛋', 'egg_dairy', 2.0, '个', '新鲜鸡蛋为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '葱花', 'vegetable', NULL, '适量', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '水', 'other', 500.0, 'ml', '清水即可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '盐', 'seasoning', 2.0, 'g', '根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '油', 'oil', 5.0, 'ml', '食用油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '香油', 'oil', NULL, '几滴', '出锅前加入提香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '虾仁', 'seafood', NULL, '适量（可选）', '提前煮熟或用生虾仁', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '牛肉高汤', 'other', 2000.0, 'mL', '可用〇汤宝代替', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '牛肉', 'meat', 1000.0, 'g', '可选用牛腩肉或牛尾肉', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '番茄罐头', 'vegetable', 8.0, '罐', '每罐约400g，可用新鲜番茄替代但风味欠佳', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '番茄膏', 'sauce', 20.0, 'g', '增加番茄风味', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '马铃薯', 'vegetable', 1600.0, 'g', '切2cm块', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '洋葱', 'vegetable', 400.0, 'g', '切1cm见方小丁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '胡萝卜', 'vegetable', 400.0, 'g', '切1cm见方小丁', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '欧芹', 'vegetable', 400.0, 'g', '切1cm见方小丁', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '包菜', 'vegetable', 800.0, 'g', '去梗后手撕至2cm片', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '红肠', 'meat', 400.0, 'g', '切2cm块', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '橄榄油', 'oil', 20.0, 'mL', '用于蔬菜的烹制，可以用植物油代替', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '植物油', 'oil', 20.0, 'mL', '用于牛肉的烹制，不能用橄榄油代替', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '盐', 'seasoning', 72.0, 'g', '分次加入', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '黑胡椒', 'spice', 12.0, 'g', '分次加入', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '饮用水', 'other', 1.0, 'L', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '大米', 'staple', 50.0, 'g', '选择优质大米', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '糯米', 'staple', 50.0, 'g', '增加粘稠度', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '薏米', 'staple', 50.0, 'g', '可选，增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '黑米', 'staple', 50.0, 'g', '可选，增加颜色和营养', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '小米', 'staple', 50.0, 'g', '可选，增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '莲子', 'dry_goods', 25.0, 'g', '去芯，养心安神', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '绿豆', 'staple', 25.0, 'g', '可选，清热解毒', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '红豆', 'staple', 25.0, 'g', '可选，补血', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '花生', 'nut', 25.0, 'g', '可选，增加香味', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '黄豆', 'staple', 25.0, 'g', '可选，增加蛋白质', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '豌豆', 'staple', 25.0, 'g', '可选，增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '红腰豆', 'staple', 25.0, 'g', '可选，增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '红枣', 'fruit', 25.0, 'g', '切成小片，增加甜味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '桂圆', 'fruit', 25.0, 'g', '去种龙眼干，增加甜味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '栗子', 'nut', 25.0, 'g', '可选，增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '去壳核桃', 'nut', 25.0, 'g', '可选，增加香味', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '葡萄干', 'fruit', 25.0, 'g', '可选，增加甜味', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '冰糖', 'seasoning', 10.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '西红柿', 'vegetable', 1.0, 'g', '选择成熟度高、颜色鲜艳的西红柿', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '鸡蛋', 'egg_dairy', 1.0, '个', '根据个人口味调整数量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '香油', 'oil', 2.0, '滴', '用于提香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '味素', 'seasoning', 5.0, '克（可选）', '可根据个人喜好添加或不加', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '盐', 'seasoning', 5.0, '克', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '葱', 'vegetable', 5.0, '克', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '姜', 'spice', 5.0, '克', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '蒜', 'vegetable', 5.0, '克', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '食用油', 'oil', 15.0, '毫升', '炒菜用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '金针菇', 'mushroom', 400.0, '克', '选择新鲜、无异味的金针菇', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '鸡蛋', 'egg_dairy', 1.0, '个（可选）', '根据个人喜好决定是否加入', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '食盐', 'seasoning', 1.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '味精', 'seasoning', 2.5, 'g', '可根据个人喜好增减或不加', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '水', 'other', 1.5, '约1.5升', '水量需没过食材', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '香油', 'oil', NULL, '几滴', '用于提香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '排骨', 'meat', 500.0, 'g', '选择带有一定肥肉的排骨，口感更佳', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '陈皮', 'spice', 1.0, 'g', '选用8-20年制的陈皮，香气更浓郁', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '西洋参', 'other', 9.0, 'g', '切片厚度约为2mm', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '石斛', 'other', 6.0, 'g', '每颗长度约2cm', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '玉竹', 'other', 5.0, 'g', '每片长度约3cm', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '麦冬', 'other', 7.0, 'g', '每个长度约1cm', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '食盐', 'seasoning', 5.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '黄瓜', 'vegetable', 1.0, '根', '可去皮，薄片可用刮皮刀刮制', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '皮蛋', 'egg_dairy', 2.0, '个', '切块前可抹香油防粘刀', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '大蒜', 'vegetable', 2.0, '瓣', '拍松后对半切', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '小葱', 'vegetable', NULL, '适量', '切末，出锅前撒用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '食用油', 'oil', 10.0, 'g', '推荐猪油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '盐', 'seasoning', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '鸡精', 'seasoning', 0.5, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '米饭', 'staple', 200.0, 'g', '最好使用隔夜饭', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '可乐', 'other', 160.0, 'ml', '含糖或无糖均可，含糖可乐口感更好', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '鸡蛋', 'egg_dairy', 3.0, '个', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '火腿肠', 'meat', 20.0, 'g', '切丁，可选午餐肉', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '油', 'oil', 25.0, 'ml', '植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '生抽', 'sauce', 15.0, 'ml', '酱油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '老抽', 'sauce', 7.5, 'ml', '如果使用无糖可乐，追加5ml；如果不使用豆瓣酱，追加5ml', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '蚝油', 'sauce', 5.0, 'ml', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '豆瓣酱', 'sauce', 7.5, 'ml', '可选，增加辣味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '葱花', 'vegetable', 5.0, 'g', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '胡椒粉', 'spice', 1.0, 'g', '白胡椒或黑胡椒均可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '大米', 'staple', 300.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '水', 'other', 310.0, 'ml', '偏硬用300 ml，偏软用325 ml；若加冬笋则额外+20 ml', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '青菜（矮脚青菜/上海青）', 'vegetable', 400.0, 'g', '菜梗与菜叶分开切配', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '咸肉（淡咸肉）', 'meat', 150.0, 'g', '若非淡咸肉，建议混入新鲜五花肉丁、减量或瘦肉部分泡5%糖水20分钟', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '冬笋', 'vegetable', 100.0, 'g', '可选；需冷水下锅煮10分钟去涩味', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '猪油', 'oil', 15.0, 'g', '其中10 g用于煸炒，5 g用于出锅翻拌', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '料酒', 'seasoning', 15.0, 'ml', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '白糖', 'seasoning', 0.0, 'g', '可选；用于中和咸味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '白胡椒粉', 'spice', 1.0, 'g', '可选；出锅前加入', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '面粉', 'staple', 200.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '冷水', 'other', 150.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '芝麻香油', 'oil', 2.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '瘦肉末', 'meat', 250.0, 'g', '生重', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '肥肉末', 'meat', 20.0, 'g', '生重，不喜可不加', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '姜', 'spice', 3.0, 'g', '切成末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '葱', 'vegetable', 15.0, 'g', '切成末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '盐', 'seasoning', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '蚝油', 'sauce', 2.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '香油', 'oil', 2.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '生抽', 'sauce', 2.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '鸡蛋', 'egg_dairy', 1.0, '个', '只用蛋清', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '韭菜', 'vegetable', 100.0, 'g', '洗净切短至 3mm 以下长度', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '面条', 'staple', 200.0, 'g', '可选择手工面条、龙须面或泡面面饼', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '猪肉', 'meat', 150.0, 'g', '切成薄片或小块', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '鸡蛋', 'egg_dairy', 2.0, '个', '打散备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '豆腐皮', 'tofu', 100.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '生菜', 'vegetable', 100.0, 'g', '洗净切段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '胡萝卜', 'vegetable', 1.0, '根', '去皮切片', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '青椒', 'vegetable', 1.0, '个', '去籽切片', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '番茄', 'vegetable', 1.0, '个', '切块', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '香菇', 'mushroom', 5.0, '朵', '提前泡发，切片', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '盐', 'seasoning', NULL, '适量', '根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '胡椒粉', 'spice', NULL, '适量', '根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '香油', 'oil', 1.0, '茶匙', '提味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '冷水', 'other', 800.0, 'ml', '用于煮面', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '年糕/白粿', 'staple', 250.0, 'g', '形状不限', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '小葱', 'vegetable', 2.0, '根', '切葱花，将葱白和葱叶分开', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '食用油', 'oil', 50.0, 'ml', '分两次使用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '酱油', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '盐', 'seasoning', 1.0, 'g', '按口味喜好调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '鸡蛋', 'egg_dairy', 1.0, '个（可选）', '打散备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '青菜', 'vegetable', NULL, '适量（可选）', '切小段备用', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '方便面', 'staple', 1.0, '包', '选择你喜欢的品牌', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '鸡蛋', 'egg_dairy', 1.0, '个', '新鲜鸡蛋为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '火腿肠', 'meat', 1.0, '根', '可选，切成1cm宽的小块', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '盐', 'seasoning', 2.0, 'g', '用于调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '食用油', 'oil', 10.0, 'ml', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '河粉', 'staple', 500.0, 'g', '建议购买袋装鲜河粉', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '猪肉/牛肉', 'meat', 300.0, 'g', '切细条状', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '黄瓜', 'vegetable', 60.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '面筋块', 'tofu', 60.0, 'g', '处理后挤干水分', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '绿豆芽', 'vegetable', 60.0, 'g', '焯水备用', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '鸡蛋', 'egg_dairy', 2.0, '个', '打碎，蛋清和蛋黄分开使用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '蒜瓣', 'vegetable', 4.0, '个', '拍碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '小葱', 'vegetable', 2.0, '根', '切碎，葱白和葱叶分开', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '盐', 'seasoning', 20.0, 'g', '或按个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '味精', 'seasoning', 4.0, 'g', '或按个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '孜然粉', 'spice', 6.0, 'g', '或按个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '胡椒粉', 'spice', NULL, '适量', '用于腌制肉丝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '老抽', 'sauce', 20.0, 'ml', '提色用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '生抽', 'sauce', 30.0, 'ml', '提鲜用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '淀粉', 'dry_goods', 15.0, 'g', '用于腌制肉丝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '馒头', 'staple', 2.0, '个（隔天略硬更好）', '切成小块或小片', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '盐', 'seasoning', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '油', 'oil', 20.0, 'ml（花生油或芝麻油更好）', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '孜然粉', 'spice', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '辣椒粉', 'spice', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '五香粉', 'spice', 3.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '小葱', 'vegetable', 2.0, '棵', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '鸡蛋', 'egg_dairy', 2.0, '个（可选）', '打散', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '猪肉（瘦肉丁）', 'meat', 150.0, 'g', '选择新鲜瘦肉，切成小丁', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '面条（普通面条）', 'staple', 250.0, 'g', '选择劲道的面条，避免使用细面', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '葱', 'vegetable', 15.0, 'g', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '蒜', 'vegetable', 10.0, 'g', '切末备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '黄瓜', 'vegetable', 30.0, 'g', '切丝备用', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '白菜', 'vegetable', 30.0, 'g', '切丝备用', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '胡萝卜', 'vegetable', 30.0, 'g', '切丝备用', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '豆瓣酱', 'sauce', 20.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '甜面酱', 'sauce', 20.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '食用油', 'oil', 10.0, 'g', '适量即可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '水', 'other', NULL, '适量', '用于煮面', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '糖', 'seasoning', 5.0, 'g', '可选，用于提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '料酒', 'seasoning', 1.0, '汤匙', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '热干面特有的碱水面', 'staple', 250.0, 'g', '选择新鲜的碱水面', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '小葱', 'vegetable', 10.0, 'g', '切葱花备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '酸豆角', 'vegetable', 20.0, 'g', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '肉末', 'meat', 30.0, 'g', '提前炒熟备用', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '蒜水', 'seasoning', 30.0, 'ml', '用蒜末加水浸泡制成', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '肉汤汁', 'sauce', 30.0, 'ml', '用猪骨或鸡骨熬制的高汤', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '萝卜干', 'vegetable', 50.0, 'g', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '芝麻酱', 'sauce', 40.0, 'ml', '选择纯芝麻酱', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '辣椒油', 'oil', 0.0, 'ml', '根据个人口味添加', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '胡椒粉', 'spice', 0.5, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '酱油', 'sauce', 5.0, 'ml', '生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '食盐', 'seasoning', 3.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '鸡精', 'seasoning', 0.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '鸡腿', 'meat', 500.0, '只', '选择新鲜、肉质饱满的鸡腿', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '料酒', 'seasoning', 15.0, 'ml', '用于去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '生抽', 'sauce', 30.0, 'ml', '调味提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '蜂蜜', 'other', 15.0, 'ml', '可选，没有时使用白糖20g + 玉米淀粉5g + 0.5ml柠檬汁或醋代替', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '黑胡椒碎', 'spice', 5.0, 'g', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '黑胡椒粉', 'spice', 5.0, 'g', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '盐', 'seasoning', 2.5, 'g', '适量调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '西兰花', 'vegetable', 50.0, 'g', '焯水后更脆嫩，没有可用不辣的青椒代替', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '胡萝卜', 'vegetable', 50.0, 'g', '切片或切条，增加色彩和营养', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '老抽', 'sauce', 12.0, 'ml', '调色增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '大蒜', 'vegetable', 10.0, 'g', '切片或拍碎，增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '生姜', 'vegetable', 10.0, 'g', '切片，去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '食用油', 'oil', 15.0, 'ml', '适量，根据实际情况调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '清水', 'other', 30.0, 'ml', '用于调制酱汁', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '米饭', 'staple', 300.0, 'g', '提前煮好，保持温热', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '泡面', 'staple', 1.0, '包', '选择你喜欢的品牌和口味', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '鸡蛋', 'egg_dairy', 1.0, '个', '新鲜鸡蛋为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '水', 'other', 550.0, 'ml', '根据锅的大小调整水量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '米饭', 'staple', 200.0, '克', '推荐使用粳米', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '猪油', 'oil', 15.0, 'g', '室温软化或微波炉加热至融化', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '生抽', 'sauce', 5.0, 'ml', '推荐用李锦记或海天', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '老抽', 'sauce', 2.0, '毫升', '用于调色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '蚝油', 'sauce', 8.0, '克（可选）', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '葱花', 'vegetable', 5.0, '克（可选）', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '猪油渣', 'meat', 5.0, '克（可选）', '增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '挂面', 'staple', 120.0, '克', '选择中等粗细的挂面', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '老干妈辣椒酱', 'sauce', 1.0, 'ml', '根据个人口味调整用量', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '酱油', 'sauce', 1.0, 'ml', '使用生抽提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '水', 'other', 1.0, '升', '用于煮面', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '米饭', 'staple', 240.0, 'g', '提前煮好备用', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '鸡蛋', 'egg_dairy', 4.0, '个', '新鲜鸡蛋为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '猪肉馅', 'meat', 300.0, 'g', '选择肥瘦相间的猪肉馅', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '老抽', 'sauce', 10.0, 'ml', '用于上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '生抽', 'sauce', 25.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '醋', 'seasoning', 20.0, 'ml', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '红葱油', 'oil', 10.0, 'g（可选）', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '葱', 'vegetable', 10.0, 'g', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '油', 'oil', 30.0, 'ml', '炒菜用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '糖', 'seasoning', 15.0, 'g', '可根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '干面条', 'staple', 320.0, 'g', '即4份×80 g/份；相当于约600 g湿面条', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '小葱', 'vegetable', 100.0, 'g', '用于制作葱油酱汁；另可预留少许炸葱段作配料', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '食用油', 'oil', 100.0, 'ml', '用于煸炒葱段制葱油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '生抽', 'sauce', 60.0, 'ml', '用于调制葱油酱汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '老抽', 'sauce', 20.0, 'ml', '用于上色和增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '白糖', 'seasoning', 15.0, 'g', '用于提鲜平衡咸味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '猪五花肉', 'meat', 350.0, 'g', '去皮，切2cm×6cm×0.5cm薄片', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '鲜面条', 'staple', 500.0, 'g', '必须用最细面条；若不可得，可参考焖面做法替代', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '芹菜', 'vegetable', 2.0, '根（中等大小）', '去叶、去根部2cm，对半切后切2cm段', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '大葱', 'vegetable', 10.0, 'cm', '切0.2cm薄片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '大蒜', 'vegetable', 5.0, '瓣', '去皮切粒', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '姜', 'spice', 20.0, 'g', '切细丝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '青椒', 'vegetable', 2.0, '个', '选配，切块或切丝', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '干红椒', 'spice', 3.0, '个', '选配', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '花椒', 'spice', 20.0, '粒', '选配', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '食用油', 'oil', 3.0, 'ml', '花生油最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '生抽', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '老抽', 'sauce', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '料酒', 'seasoning', NULL, '适量', '原文未标量，保留模糊表述', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '盐', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '五香粉', 'spice', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '鸡蛋', 'egg_dairy', 2.0, '个', '建议使用土鸡蛋，口感更香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '洋葱', 'vegetable', 30.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '胡萝卜', 'vegetable', 30.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '火腿肠或鸡胸肉', 'meat', 50.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '玉米粒和青豆', 'vegetable', 30.0, 'g', '青豆可选', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '米饭', 'staple', 200.0, 'g', '建议用隔夜饭', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '番茄酱', 'sauce', 20.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '食用油', 'oil', 15.0, 'ml', '建议使用植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '牛奶', 'egg_dairy', 10.0, 'ml', '与鸡蛋混合，使蛋皮更嫩', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '冷饭', 'staple', 500.0, 'ml', '最好使用隔夜冷饭', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '鸡蛋', 'egg_dairy', 2.0, '个', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '火腿', 'meat', 50.0, 'g', '切丁', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '黄瓜', 'vegetable', 30.0, 'g', '可选，切丁', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '胡萝卜', 'vegetable', 30.0, 'g', '可选，切丁', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '油', 'oil', 2.0, '汤匙', '食用油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '盐', 'seasoning', 1.0, '/2茶匙', '根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '胡椒粉', 'spice', 1.0, '/4茶匙', '适量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '生抽', 'sauce', 1.0, '汤匙', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '香葱', 'vegetable', 1.0, '根', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '熟肉（如灯影牛肉丝、午餐肉、腊肠等）', 'meat', 50.0, 'g', '可选，切丁', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '袋装螺蛳粉', 'staple', 1.0, 'g', '选择品质较好的品牌', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '水', 'other', 1.0, 'L', '用于煮米粉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '蕨根粉', 'staple', 150.0, '克', '提前用冷水浸泡30分钟', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '油泼辣子', 'seasoning', 4.0, '汤匙', '', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '酱油', 'sauce', 6.0, '汤匙', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '香醋', 'sauce', 4.0, '汤匙', '', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '小米辣', 'vegetable', 2.0, '个（可选）', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '蒜', 'vegetable', 2.0, '瓣（可选）', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '葱', 'vegetable', 1.0, '根（可选）', '切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '盐', 'seasoning', 2.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '糖', 'seasoning', 2.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '小汤圆', 'staple', 250.0, '克', '选择新鲜或冷冻的小汤圆', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '醪糟', 'other', 50.0, '克', '选择品质好的醪糟', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '白糖', 'seasoning', 30.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '枸杞', 'fruit', 10.0, '颗', '可选，提前泡软', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '水', 'other', 600.0, '毫升', '根据需要可以适当增减', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '韭菜', 'vegetable', 500.0, 'g', '选择新鲜、叶片宽厚的韭菜', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '虾仁', 'seafood', 100.0, 'g', '新鲜或冷冻虾仁，去壳去肠线', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '鸡蛋', 'egg_dairy', 3.0, '枚', '中等大小的鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '香油', 'oil', 10.0, 'ml', '增加香味', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '盐', 'seasoning', 5.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '面粉', 'staple', 250.0, 'g', '普通中筋面粉', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '水', 'other', 120.0, 'ml', '根据面团软硬度调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '烧卖皮', 'staple', 30.0, 'g', '直径8–10cm；可用大馄饨皮或饺子皮擀薄替代', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '猪肉末', 'meat', 300.0, 'g', '肥瘦比3:7；低脂版用猪里脊或猪前腿肉280g', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '生姜末', 'vegetable', 5.0, 'g', '5g更突出肉鲜，10g风味更重', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '葱末（仅绿部）', 'vegetable', 10.0, 'g', '10g更清淡，20g近似饺子风味', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '生抽', 'sauce', 15.0, 'mL', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '料酒', 'seasoning', 10.0, 'mL', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '盐', 'seasoning', 3.0, 'g', '若用浓汤宝则减至0–2g', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '糖', 'seasoning', 2.0, 'g', '可选，提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '白胡椒粉', 'spice', 2.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '芝麻油', 'oil', 5.0, 'mL', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '高汤', 'other', 30.0, 'mL', '或用浓汤宝6g+30mL水替代', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '浓汤宝', 'seasoning', 6.0, 'g', '家乐牌约1/8块，需先用15mL热水化开再兑15mL常温水', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '冬笋', 'vegetable', 50.0, 'g', '可选，切细丁', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '皮冻', 'meat', 100.0, 'g', '推荐，切小丁，冷藏后使用更易包', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '香菇', 'mushroom', 75.0, 'g', '鲜香菇；或干香菇30g泡发后挤干切碎', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '虾仁', 'seafood', 100.0, 'g', '约20–25个，可选，顶部装饰用', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '猪油或鸡油', 'oil', 15.0, 'g', '低脂版中用于补偿口感；常规版可省略（因肥肉已含脂）', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '复配食品增稠剂', 'other', 1.2, 'g', 'κ-卡拉胶45%、瓜尔胶35%、氯化钾20%；低脂版专用；可等量替换为玉米淀粉2g', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '冷水', 'other', 10.0, 'mL', '仅低脂版：用于溶解增稠剂', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '开水', 'other', 25.0, 'mL', '仅低脂版：用于激活增稠剂成凝胶', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '快熟面', 'staple', 1.0, 'g', '选择你喜欢的品牌，但不需要调味包', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '水', 'other', 1.0, '升', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '麻油', 'oil', 1.0, 'ml', '选择品质好的麻油', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '老抽', 'sauce', 1.0, 'ml', '用于上色和提味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '盐', 'seasoning', 1.0, 'g', '可选，根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '胡椒粉', 'spice', 1.0, 'g', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '生抽', 'sauce', 1.0, 'ml', '可选，增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '半干荞麦面', 'staple', 100.0, 'g', '建议选择口感较好的半干荞麦面', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '娃娃菜', 'vegetable', 8.0, 'g', '洗净备用', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '生菜', 'vegetable', 6.0, 'g', '洗净备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '火锅底料', 'seasoning', 25.0, 'g', '推荐使用清油火锅底料', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '花生酱', 'sauce', 15.0, 'g', '增加风味', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '全脂牛奶', 'egg_dairy', 150.0, 'ml', '提升汤底的浓郁度', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '生抽', 'sauce', 6.0, 'ml', '调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '辣椒油', 'oil', 10.0, 'ml', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '醋', 'seasoning', 20.0, 'ml', '可选，根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '花椒油', 'oil', 10.0, 'ml', '增加麻味', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '水', 'other', 500.0, 'ml', '用于煮面', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '油麦菜', 'vegetable', 200.0, 'g', '选择新鲜、叶片鲜绿的油麦菜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '芝麻酱', 'sauce', 10.0, 'ml', '可用花生酱代替', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '酱油', 'sauce', 5.0, 'ml', '生抽为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '醋', 'seasoning', 15.0, 'ml', '陈醋或米醋均可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '蚝油', 'sauce', 10.0, 'ml', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '白糖', 'seasoning', 5.0, 'g', '调节酸甜度', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '香油', 'oil', 5.0, 'ml', '提香', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '蒜', 'vegetable', 2.0, '瓣', '拍碎切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '盐', 'seasoning', NULL, '适量', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '豆腐', 'tofu', 250.0, 'g', '推荐北豆腐或老豆腐', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '小葱', 'vegetable', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '大蒜', 'vegetable', 2.0, '瓣', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '生抽', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '香油', 'oil', 5.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '醋', 'seasoning', 5.0, 'ml', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '白糖', 'seasoning', 2.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '辣椒油', 'oil', 5.0, 'ml', '可选', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '金针菇', 'mushroom', 150.0, 'g', '约1小包', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '小葱', 'vegetable', 5.0, 'g', '洗净切葱花', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '大蒜', 'vegetable', 2.0, '瓣', '去皮切末；未提供克重，按常规1瓣≈3 g，但原文未换算，故保留原始表述', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '生抽', 'sauce', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '醋', 'seasoning', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '白糖', 'seasoning', 3.0, 'g', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '香油', 'oil', 5.0, 'ml', '可选', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '辣椒油', 'oil', 5.0, 'ml', '可选', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '黄瓜', 'vegetable', 200.0, '克', '选择新鲜、脆嫩的黄瓜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '醋', 'seasoning', 7.5, 'ml', '使用米醋或陈醋均可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '酱油', 'sauce', 5.0, 'ml', '生抽为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '蒜', 'vegetable', 3.0, '瓣', '根据个人口味调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '盐', 'seasoning', 0.4, 'g', '适量增减以适应个人口味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '香油', 'oil', 5.0, 'ml', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '蚝油', 'sauce', 5.0, '毫升/份', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '茄子', 'vegetable', 1.0, 'g', '选择新鲜、表皮光滑的茄子', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '土豆', 'vegetable', 1.0, 'g', '选择质地紧实的土豆', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '尖椒', 'vegetable', 2.0, 'g', '选择颜色鲜艳、无斑点的青椒', '2025-12-28 19:17:19', '2025-12-28 12:05:36');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '葱', 'vegetable', 1.0, 'g', '去根洗净，切段', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '姜', 'spice', 10.0, 'g', '去皮，切成末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '蒜', 'vegetable', 3.0, 'g', '去皮，剁碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '豆瓣酱', 'sauce', 1.0, 'g', '根据口味调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '生抽', 'sauce', 1.0, 'ml', '用于调味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '盐', 'seasoning', 1.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '糖', 'seasoning', 1.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '淀粉', 'dry_goods', 1.0, 'g', '调成水淀粉备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '食用油', 'oil', NULL, '适量', '用于煎炸', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '日本豆腐', 'tofu', 300.0, '个', '选择质地细腻、口感嫩滑的日本豆腐', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '青椒', 'vegetable', 120.0, '个', '选择新鲜、颜色鲜艳的青椒', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '胡萝卜', 'vegetable', 50.0, 'g', '选择新鲜、色泽鲜艳的胡萝卜', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '火腿肠', 'meat', 50.0, '根', '可选，选择口感好的火腿肠', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '黑木耳', 'mushroom', 30.0, 'g', '可选，提前泡发好', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '洋葱', 'vegetable', 30.0, 'g', '可选，选择新鲜、无烂斑的洋葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '生粉', 'staple', 80.0, 'g', '用于裹豆腐，使外皮酥脆', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '蒜', 'vegetable', 10.0, '瓣', '切碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '油', 'oil', 160.0, 'ml', '煎豆腐用，能没过一大半就行', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '生抽', 'sauce', 8.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '蚝油', 'sauce', 15.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '盐', 'seasoning', 2.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '鸡精', 'seasoning', 3.0, 'g', '可选，调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '白砂糖', 'seasoning', 10.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '番茄酱', 'sauce', 15.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '玉米粒', 'vegetable', 200.0, 'g', '建议使用甜玉米，可用罐头甜玉米，也可自备煮熟', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '熟松子仁', 'nut', 30.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '胡萝卜', 'vegetable', 50.0, 'g', '切小丁，可省略', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '食用油', 'oil', 15.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '白砂糖', 'seasoning', 10.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '盐', 'seasoning', 1.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '淀粉', 'dry_goods', 5.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '水', 'other', 20.0, 'ml', '用于调淀粉水', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '叶菜类蔬菜', 'vegetable', 400.0, 'g', '如小白菜、菠菜等，选择新鲜嫩绿的', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '食用油', 'oil', 2.0, 'ml', '建议使用花生油或菜籽油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '盐', 'seasoning', 3.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '蚝油', 'sauce', 3.0, 'ml（可选）', '增加风味，可不加', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '鸡蛋', 'egg_dairy', 4.0, '个', '新鲜鸡蛋最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '小米辣', 'vegetable', 10.0, '个', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '小葱', 'vegetable', 10.0, 'g', '切段备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '蒜', 'vegetable', 5.0, 'g', '约2瓣', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '食用油', 'oil', 35.0, 'mL', '用于炒制', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '香醋', 'sauce', 15.0, 'mL', '推荐使用老恒和酿造香醋', '2025-12-28 19:17:19', '2025-12-28 12:06:06');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '生抽', 'sauce', 10.0, 'mL', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '蚝油', 'sauce', 10.0, 'g', '可选但推荐', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '白糖', 'seasoning', 0.0, 'g', '可选，用于提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '水', 'other', 30.0, 'mL', '用于调制料汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '花菜', 'vegetable', 300.0, 'g（约1/2中等大小的花菜）', '选择新鲜、紧实的花菜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '大蒜', 'vegetable', 2.0, '瓣', '去皮切片', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '盐', 'seasoning', 3.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '食用油', 'oil', 15.0, 'ml', '建议使用植物油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '饮用水', 'other', 1000.0, 'ml（焯水用）', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', '南瓜', 'vegetable', 600.0, 'g', '建议使用老南瓜，更甜更面。如果喜欢可以不去皮蒸，但需要彻底洗净。', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', '饮用水', 'other', 1000.0, 'ml', '用于蒸锅', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '茄子', 'vegetable', 3.0, 'g', '选择新鲜、皮薄肉厚的茄子', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '八角', 'spice', 2.0, '个', '强烈推荐使用，增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '虾皮', 'seafood', 10.0, 'g', '可选，增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '香葱', 'vegetable', 4.0, '根', '切葱花备用', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '肉末', 'meat', 100.0, 'g', '可选，增加风味', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '酱油', 'sauce', 80.0, 'ml', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '糖', 'seasoning', 10.0, 'g', '可选，提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '醋', 'seasoning', 20.0, 'ml', '可选，增加酸味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '菜籽油或花生油', 'oil', NULL, '适量', '油量要多，保证茄子不吸油', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '上海青', 'vegetable', 100.0, 'g', '选择新鲜、叶片饱满的青菜', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '食用油', 'oil', 10.0, 'ml', '花生油或植物油均可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '食盐', 'seasoning', 2.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '白糖', 'seasoning', 5.0, 'g', '可选，用于提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '皮蛋', 'egg_dairy', 2.0, 'g', '选择新鲜、无裂纹的皮蛋', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '内酯豆腐', 'tofu', 1.0, 'g', '选择质地细腻的内酯豆腐', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '生抽', 'sauce', 15.0, 'ml', '选择优质生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '白砂糖', 'seasoning', 2.5, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '镇江香醋', 'seasoning', 15.0, 'ml', '推荐使用镇江香醋', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '香油', 'oil', 15.0, 'ml', '可选，增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '辣椒油', 'oil', 10.0, 'ml', '可选，根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '花生碎', 'nut', 10.0, 'g', '可选，增加口感', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '葱花', 'vegetable', 15.0, 'g', '可选，增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '香菜', 'vegetable', 1.0, 'g', '可选，增加风味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '豆角', 'vegetable', 250.0, 'g', '选择新鲜、色泽鲜绿的豆角', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '小米椒', 'spice', 2.0, '个', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '葱', 'vegetable', 15.0, 'g', '切成葱花', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '蒜', 'vegetable', 2.0, '瓣', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '生抽', 'sauce', 6.0, 'ml', '约1茶匙', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '老抽', 'sauce', 2.0, 'ml', '约半茶匙', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '蚝油', 'sauce', 6.0, 'ml', '约1茶匙', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '盐', 'seasoning', 6.0, 'g', '约1茶匙', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '食用油', 'oil', 15.0, 'ml', '约1汤匙', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '青茄子', 'vegetable', 1.0, 'g', '选择新鲜、表皮光滑的茄子', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '青辣椒', 'vegetable', 1.0, 'g', '选择新鲜、辣度适中的青椒', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '洋葱', 'vegetable', 100.0, 'g', '选择新鲜、无腐烂的洋葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '西红柿', 'vegetable', 1.0, 'g', '选择成熟、多汁的西红柿', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '大葱', 'vegetable', NULL, '半根', '选择新鲜的大葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '大蒜', 'vegetable', 3.0, '瓣', '选择新鲜、饱满的大蒜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '盐', 'seasoning', NULL, '适量', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '酱油', 'sauce', 2.0, 'ml', '建议使用生抽和老抽混合，比例为2:1', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '鸡蛋', 'egg_dairy', 1.0, '个', '选择新鲜的鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '面粉', 'staple', 150.0, '克', '普通面粉即可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '淀粉', 'dry_goods', 37.5, '克', '玉米淀粉或土豆淀粉均可', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '食用油', 'oil', NULL, '适量', '用于炸制和炒制', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '老豆腐', 'tofu', 400.0, '块', '选择质地较硬的老豆腐', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '鸡蛋', 'egg_dairy', 2.0, '个', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '生抽', 'sauce', 20.0, 'g（约2汤匙）', '优质生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '老抽', 'sauce', 5.0, 'g（约半汤匙）', '用于上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '蚝油', 'sauce', 10.0, 'g（约1汤匙）', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '白糖', 'seasoning', 10.0, 'g（约1汤匙）', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '玉米淀粉', 'dry_goods', 50.0, 'g', '用于裹粉', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '食用油', 'oil', NULL, '适量', '煎炸用油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '清水', 'other', 200.0, 'ml', '调制酱料', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '茄子', 'vegetable', 1.0, 'g', '选择新鲜、皮薄的长条茄子', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '土豆', 'vegetable', 1.0, 'g', '选择表皮光滑、无芽眼的土豆', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '猪肉', 'meat', 180.0, '克', '选用五花肉或瘦肉，切成丝', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '青辣椒', 'vegetable', 50.0, '克', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '酱油', 'sauce', 15.0, '毫升', '使用生抽提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '盐', 'seasoning', 5.0, '克', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '蒜', 'vegetable', 3.0, '瓣', '拍碎备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '食用油', 'oil', 13.0, '毫升', '适量增减', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '白豆腐', 'tofu', 400.0, '块', '选择质地较硬的北豆腐', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '葱', 'vegetable', 2.0, '根', '选用新鲜的小葱', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '青辣椒', 'vegetable', 1.0, '只', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '盐', 'seasoning', 6.0, '克', '根据个人口味适量调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '鸡精', 'seasoning', 3.0, '克', '可选，也可用味精或鸡粉代替', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '食用油', 'oil', 50.0, '毫升', '根据锅具大小和火候适当增减', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '西兰花', 'vegetable', 200.0, 'g', '约1/2个中等大小西兰花，切小朵', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '大蒜', 'vegetable', 3.0, '瓣', '约10 g，切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '生抽', 'sauce', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '蚝油', 'sauce', 5.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '白糖', 'seasoning', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '饮用水', 'other', 1030.0, 'ml', '1000 ml焯水 + 30 ml调汁', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '食用油', 'oil', 10.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '长茄子', 'vegetable', 1.0, 'g', '选择新鲜、无斑点的茄子', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '蒲烧汁', 'sauce', 100.0, 'ml', '可以买现成的蒲烧汁或自制', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '蜂蜜', 'other', 20.0, 'ml', '增加甜味和光泽', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '白糖', 'seasoning', 15.0, 'ml', '调节甜度', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '生抽', 'sauce', 40.0, 'ml', '增加咸味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '老抽', 'sauce', 10.0, 'ml', '上色', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '料酒', 'seasoning', 20.0, 'ml', '去腥增香', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '水', 'other', 100.0, 'ml', '用于调制酱汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '食用油', 'oil', NULL, '适量', '根据锅具类型调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '生菜', 'vegetable', 1.0, 'g', '推荐使用罗马生菜或玻璃生菜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '蚝油', 'sauce', 6.0, 'ml', '选择品质较好的蚝油', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '大蒜', 'vegetable', 4.0, '瓣', '做成蒜泥或切碎', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '生抽', 'sauce', 6.0, 'ml', '用于调汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '盐', 'seasoning', 0.5, 'g', '用于焯水和调汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '白糖', 'seasoning', 1.0, 'g', '用于调汁', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '食用油', 'oil', 5.0, 'ml', '用于炒制蒜末', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '西红柿', 'vegetable', 2.0, 'g', '选择成熟度高、颜色鲜红的西红柿', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '鸡蛋', 'egg_dairy', 3.0, '个', '新鲜鸡蛋为佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '食用油', 'oil', 12.0, 'ml', '植物油或花生油均可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '盐', 'seasoning', 3.0, 'g', '根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '糖', 'seasoning', 0.0, 'g', '可选，增加甜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '葱花', 'vegetable', 0.0, 'g', '可选，增加香气', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '土豆', 'vegetable', 240.0, 'g', '选择新鲜、质地紧实的土豆，越细越长更好', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '大蒜', 'vegetable', 4.0, '瓣', '切末备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '青椒', 'vegetable', 0.5, '个', '切丝备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '红椒', 'vegetable', 0.5, '个', '切丝备用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '干辣椒', 'spice', 3.0, '个', '剪成小段备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '葱', 'vegetable', 1.0, '根', '切段备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '生抽', 'sauce', 5.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '陈醋', 'sauce', 10.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '盐', 'seasoning', 2.0, 'g', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '食用油', 'oil', 10.0, 'ml', '炒菜用', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '金针菇', 'mushroom', 1.0, 'g', '选择新鲜、无异味的金针菇', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '日本豆腐（玉子豆腐）', 'tofu', 2.0, 'g', '选择质地细腻、不易碎的日本豆腐', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '小米椒', 'spice', 3.0, 'g', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '蒜', 'vegetable', 2.0, 'g', '切末备用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '生抽', 'sauce', 15.0, 'ml', '选择品质好的生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '蚝油', 'sauce', 5.0, 'ml', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '老抽', 'sauce', 3.0, 'ml', '调色用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '糖', 'seasoning', 3.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '食用油', 'oil', 10.0, 'ml', '适量即可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '鸡蛋', 'egg_dairy', 5.0, '个', '新鲜鸡蛋', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '线椒', 'vegetable', 15.0, 'g', '约半个线椒', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '小米辣', 'vegetable', 6.0, '个', '根据个人口味调整辣度', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '豆豉', 'sauce', 15.0, 'g', '选用优质豆豉', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '蒜', 'vegetable', 10.0, '瓣', '切成细末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '小葱', 'vegetable', 3.0, '根', '切成葱花', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '玉米淀粉', 'dry_goods', 40.0, 'g', '可选，用于裹蛋片', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '食用油', 'oil', 20.0, 'ml', '根据是否裹淀粉调整用量', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '生抽', 'sauce', 15.0, 'ml', '调味用', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '蚝油', 'sauce', 15.0, 'ml', '增加鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '糖', 'seasoning', 5.0, 'g', '提鲜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '豆角', 'vegetable', 600.0, 'g', '选择新鲜、嫩绿的豆角', '2025-12-28 19:17:19', '2025-12-28 12:06:42');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '土豆', 'vegetable', 2.0, 'g', '中等大小，去皮切块', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '西红柿', 'vegetable', 2.0, 'g', '成熟，去皮切块', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '螺丝椒', 'vegetable', 4.0, '个（可选）', '去籽切条', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '盐', 'seasoning', 12.0, 'g', '根据口味调整', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '生抽', 'sauce', 12.0, 'ml', '增色提味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '五香粉', 'spice', 6.0, 'g', '增加香气', '2025-12-28 19:17:19', '2025-12-28 12:05:02');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '蚝油', 'sauce', 12.0, 'ml', '提升鲜味', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '葱', 'vegetable', 1.0, '根', '切花', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '姜', 'spice', 4.0, 'g', '切丝', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '蒜', 'vegetable', 4.0, '瓣', '切末', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '香菜碎', 'vegetable', NULL, '适量', '可选，用于装饰', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '皮蛋', 'egg_dairy', 2.0, '个', '建议选择新鲜的皮蛋', '2025-12-28 19:17:19', '2025-12-28 12:06:23');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '长条青椒（线椒）', 'vegetable', 4.0, '根（每根长约10-15cm，宽约2-4cm）', '选择新鲜、无斑点的青椒', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '葱', 'vegetable', 10.0, '根', '使用葱绿部分最佳', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '蒜', 'vegetable', 3.0, '瓣', '新鲜的大蒜', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '小米辣', 'vegetable', 3.0, '颗', '可选，根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 12:05:17');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '食用油', 'oil', 10.0, 'ml', '普通植物油即可', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '生抽', 'sauce', 15.0, 'ml', '选择品质较好的生抽', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '陈醋', 'sauce', 15.0, 'ml', '选择品质较好的陈醋', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '白糖', 'seasoning', 6.0, 'g', '白砂糖', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '香油', 'oil', 5.0, 'ml', '芝麻香油', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '黄瓜', 'vegetable', 200.0, 'g', '约1根，洗净切半圆形片', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '鸡蛋', 'egg_dairy', 2.0, '个', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '火腿肠', 'meat', 40.0, 'g', '约1根，切半圆形片', '2025-12-28 19:17:19', '2025-12-28 12:05:48');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '红尖椒', 'vegetable', 1.0, '个', '可选，切碎', '2025-12-28 19:17:19', '2025-12-28 12:06:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '食用油', 'oil', 10.0, 'ml', '分两次使用，每次5ml', '2025-12-28 19:17:19', '2025-12-28 12:04:46');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '生抽', 'sauce', 3.0, 'ml', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');
INSERT INTO t_ingredient (recipe_id, name, category, quantity, unit, notes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '盐', 'seasoning', 2.0, 'g', '', '2025-12-28 19:17:19', '2025-12-28 12:04:29');

-- ==================== t_ingredient_category ====================

INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('meat', '肉禽类', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('seafood', '水产海鲜', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('vegetable', '蔬菜', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('mushroom', '菌菇', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('tofu', '豆制品', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('egg_dairy', '蛋奶', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('staple', '主食', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('dry_goods', '干货', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('seasoning', '调味料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('sauce', '酱料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('spice', '香辛料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('oil', '油脂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('fruit', '水果', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('nut', '坚果', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_ingredient_category (`key`, label, created_at, updated_at) VALUES ('other', '其他', '2025-12-28 19:17:19', '2025-12-28 19:17:19');

-- ==================== t_recipe ====================

INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', '咖喱炒蟹', '这道菜源自泰国，肉质饱满的青蟹搭配浓郁的咖喱酱汁，味道鲜美独特，是海鲜爱好者的绝佳选择。', '[]', 'aquatic', 4, 1, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', '响油鳝丝', '一道经典的江浙沪风味菜，鳝丝鲜嫩滑爽，以蒜香、姜末和酱汁调味，淋热猪油后香气扑鼻，口感浓郁微甜，超下饭～', '[]', 'aquatic', 3, 2, 20, 10, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', '微波葱姜黑鳕鱼', '这道菜改编自西雅图 Veil 餐厅主厨 Johnny Zhu 的母亲 Margaret Lu 的菜谱，使用微波炉快速烹饪，保留了鱼肉的鲜嫩和葱姜的香气。', '[]', 'aquatic', 3, 2, 10, 7, 17, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', '水煮鱼', '一道经典的川菜，巴沙鱼肉质鲜嫩，搭配时令蔬菜，麻辣鲜香，营养健康。', '[]', 'aquatic', 4, 3, 90, 30, 120, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', '清蒸生蚝', '一道简单而美味的海鲜佳肴，保留了生蚝的原汁原味。', '[]', 'aquatic', 3, 2, 15, 7, 22, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', '红烧鱼', '一道经典的中式家常菜，鱼肉鲜嫩，酱汁浓郁。', '[]', 'aquatic', 4, 2, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('4llgljo9sZn94bpAuM6gyX', '红烧鱼头', '这道菜以鲜美的鱼头为主料，搭配多种调料慢炖而成，口感鲜嫩，汤汁浓郁。', '[]', 'aquatic', 4, 2, 120, 30, 150, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', '红烧鲤鱼', '这道菜色泽红亮，肉质鲜嫩，味道醇厚，是经典的家常菜之一。', '[]', 'aquatic', 4, 2, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', '肉蟹煲', '一道酱香浓郁的煲类菜品，以鲜活肉蟹为主角，搭配软糯土豆和Q弹年糕，经秘制酱汁慢火炖煮，口感鲜甜微辣，汤汁拌饭尤佳。', '[]', 'aquatic', 4, 3, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', '酱炖蟹', '秋日限定咸鲜风味！蟹黄绵润裹着酱香，蟹肉清甜入味，汤汁浓郁拌饭一绝。', '[]', 'aquatic', 3, 2, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', '吐司果酱', '饱腹感的懒人快速营养早餐，2分钟搞定，简单美味。', '[]', 'breakfast', 1, 1, 1, 2, 3, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('HadyXz9faXilXk2rtI8ekC', '太阳蛋', '太阳蛋是一道简单又美味的早餐菜品，特点是蛋白凝固而蛋黄保持流动状态，口感丰富。', '[]', 'breakfast', 2, 1, 5, 4, 9, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', '完美水煮蛋', '科学家研发的循环水煮法，可同时达到蛋黄绵密、蛋白均匀凝固且保留最多营养素的效果。需精准控制温度与时间，难度较高。', '[]', 'breakfast', 5, 1, 5, 32, 37, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', '微波炉荷包蛋', '一道简单易做且富含蛋白质的菜，只需120秒内即可完成，适合忙碌早晨。', '[]', 'breakfast', 1, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', '微波炉蒸蛋', '嫩滑细腻、快速上桌的高蛋白早餐，用微波炉约10分钟完成，适合1-2人食用。', '[]', 'breakfast', 1, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', '微波炉蛋糕', '一款简单快捷的微波炉蛋糕，适合初学者尝试。只需几分钟即可完成，口感松软香甜。', '[]', 'breakfast', 1, 1, 5, 2, 7, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', '手抓饼', '外酥里嫩，层次分明的手抓饼，搭配丰富的夹心食材，美味可口。', '[]', 'breakfast', 2, 1, 30, 15, 45, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', '桂圆红枣粥', '桂圆红枣粥，甜口。补血安神，健脑益智，补养心脾。', '[]', 'breakfast', 2, 2, 20, 50, 70, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', '水煮玉米', '简单易做，保留了玉米的原汁原味，是一道健康的家常菜。', '[]', 'breakfast', 2, 1, 5, 20, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', '溏心蛋', '简单易做的溏心蛋，适合健身爱好者补充蛋白质。只需15分钟即可完成。', '[]', 'breakfast', 3, 2, 5, 10, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('kzLPHil1N60srD4j35yMEL', '煎饺', '外皮金黄酥脆，内馅鲜美多汁的传统煎饺。', '[]', 'breakfast', 2, 2, 5, 20, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('kmX1mciO957s41SmIyzTKj', '燕麦鸡蛋饼', '燕麦鸡蛋饼是极具营养、便于制作、适宜快速制作的早餐。尤其适宜热爱健身的上班族。', '[]', 'breakfast', 2, 2, 10, 10, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', '牛奶燕麦', '高蛋白，粗谷物纤维，饱腹感的懒人快速营养早餐，3分钟搞定', '[]', 'breakfast', 1, 1, 2, 3, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', '空气炸锅面包片', '健康饱肚子，适宜正在减脂期的程序员食用', '[]', 'breakfast', 1, 1, 2, 5, 7, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', '美式炒蛋', '美式炒蛋具有松软鲜嫩的口感，与平时的炒蛋不同，美式炒蛋中加入了少量牛奶，使得蛋花更加细密均匀，并且营养丰富。', '[]', 'breakfast', 2, 1, 5, 5, 10, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', '茶叶蛋', '茶香浓郁，鲜香可口的高蛋白快速营养早餐，适合2-3人享用。', '[]', 'breakfast', 3, 2, 10, 30, 40, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', '蒸水蛋', '蒸水蛋是一道简单又美味的家常菜，口感嫩滑，保留了鸡蛋的原香。', '[]', 'breakfast', 2, 2, 10, 20, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', '蒸花卷', '蒸花卷是一道简单易做的面点，口感松软、层次分明。作为快手早餐，学会做之后，再也不会早上饿肚子了。', '[]', 'breakfast', 2, 5, 60, 15, 75, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', '蛋煎糍粑', '简单易做的蛋煎糍粑，外酥里糯，美味又顶饿，十分钟即可完成。', '[]', 'breakfast', 2, 1, 5, 10, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', '金枪鱼酱三明治', '饱腹感很强的懒人早餐，营养丰富，高蛋白，大概5分钟搞定。可以配着牛奶、咖啡等饮品一起吃。', '[]', 'breakfast', 1, 1, 5, 4, 9, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', '鸡蛋三明治', '10分钟即可完成的简易美味鸡蛋三明治，适合早餐或快速午餐。', '[]', 'breakfast', 2, 1, 5, 5, 10, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('dR4o2q209C79ahYt3XhQYm', '油酥', '油酥是由面粉与热油混合调制的，通常在烙饼时涂点油酥，可以使得饼子层层分明，外酥里软，口感更佳。', '[]', 'condiment', 2, 10, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', '炸串酱料', '号称淋袜子都好吃的炸串酱料，新手友好，只需10分钟即可完成。', '[]', 'condiment', 2, 500, 5, 5, 10, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', '简易版炒糖色', '这是一份适合初学者的炒糖色教程，通过简单的步骤制作出色泽红亮、味道醇厚的糖色。', '[]', 'condiment', 4, 200, 5, 15, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('K6zvXIRbmejiJpilme4YJx', '糖醋汁', '一款经典的中式调味汁，酸甜适口，适用于多种菜肴如糖醋鱼、糖醋里脊等。', '[]', 'condiment', 2, 300, 5, 15, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', '葱油', '葱油是用热油萃取以葱为主的各类香辛料得到的产物，可以用来调制肉馅，做凉拌菜，在热炒菜中作为出锅明油使用。', '[]', 'condiment', 3, 1, 15, 25, 40, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', '蒜香酱油', '一款简单易制的调味品，适合搭配各种蒸菜或白切肉，蒜香浓郁，口感鲜美。', '[]', 'condiment', 2, 2, 5, 3, 8, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', 'B52轰炸机', 'B-52 是一款经典的分层鸡尾酒，以其独特的喝法和冰火两重天的口感而闻名。', '[]', 'drink', 3, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'Mojito莫吉托', '一种传统的古巴高球鸡尾酒，以其清新的口感和低酒精度而闻名。', '[]', 'drink', 3, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', '冬瓜茶', '冬瓜茶是一种清爽的传统饮料，适合夏季饮用，具有清热解暑的功效。', '[]', 'drink', 2, 4, 15, 120, 135, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', '可乐桶', '一款口感清爽、酒精味被可乐掩盖的威士忌鸡尾酒，适合聚会时饮用。', '[]', 'drink', 2, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', '奶茶', '一款简单易做的经典饮品，适合初学者尝试。红茶与奶的完美结合，带来浓郁香滑的口感。', '[]', 'drink', 2, 1, 5, 5, 10, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', '杨枝甘露', '这是一道清爽的港式甜品，以芒果、葡萄柚和椰奶为主要原料，搭配奇亚籽增加口感。', '[]', 'drink', 2, 1, 15, NULL, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', '酸梅汤（半成品加工）', '一款简单易做的夏日清凉饮品，酸甜可口，解渴消暑。', '[]', 'drink', 1, 4, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', '长岛冰茶', '长岛冰茶是一种高酒精度但口感柔和的鸡尾酒，不含茶却有着冰茶的口感。', '[]', 'drink', 2, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', '乡村啤酒鸭', '将鸭肉与啤酒一同炖煮成菜，使滋补的鸭肉味道更加浓厚，鸭肉不仅入口鲜香，还带有一股啤酒清香。', '[]', 'meat_dish', 4, 3, 20, 60, 80, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', '冷吃兔', '这道菜以其麻辣鲜香、口感酥脆而闻名，是川菜中的经典凉菜之一。', '[]', 'meat_dish', 4, 2, 30, 60, 90, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', '可乐鸡翅', '一道甜中带咸、色泽诱人的家常菜，适合搭配米饭或作为下酒菜。', '[]', 'meat_dish', 3, 2, 15, 30, 45, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', '咕噜肉', '咕噜肉是非常下饭的菜肴，只需一道就可以吃得津津有味，大人小孩都爱吃。而这次做的是简易版菠萝咕噜肉，利用简单的材料就可以在家做出特有风味的咕噜肉。', '[]', 'meat_dish', 4, 2, 30, 20, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', '商芝肉', '此菜色泽红润，质地软嫩，肥而不腻，有浓郁的商芝香味，是陕西省商县特有的风味菜。因商芝属于陕西特产，此菜原料获取难度较大，不易制作。', '[]', 'meat_dish', 5, 2, 30, 150, 180, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', '孜然牛肉', '这道菜以香辣的孜然和嫩滑的牛肉为主料，口感丰富，香气四溢，是一道经典的中式家常菜。', '[]', 'meat_dish', 3, 2, 45, 10, 55, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', '小炒肉', '一道色香味俱全的经典湘菜，五花肉与辣椒的完美结合，香辣可口。', '[]', 'meat_dish', 3, 2, 15, 20, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', '小米辣炒肉', '一道香辣可口的家常菜，适合喜欢重口味的朋友。', '[]', 'meat_dish', 3, 2, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', '小酥肉', '外酥里嫩、咸香微麻的中式经典油炸肉食，以猪肉条裹红薯淀粉蛋糊两次炸制而成。', '[]', 'meat_dish', 3, 3, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', '尖椒炒牛肉', '一道色香味俱全的经典家常菜，牛肉嫩滑、尖椒脆爽，口感丰富。', '[]', 'meat_dish', 3, 2, 40, 10, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', '山西过油肉', '山西传统名菜，口感鲜嫩，色泽金黄，酸辣适中。', '[]', 'meat_dish', 4, 1, 20, 15, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', '带把肘子', '这道菜肘肉酥烂不腻，肘皮胶粘，香醇味美，辅佐以葱段和甜面酱，别有一番风味。因脚爪形似把柄，故得其名，是陕西省大荔县名菜。', '[]', 'meat_dish', 5, 3, 30, 240, 270, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', '意式烤鸡', '一道简单美味的意式风味烤鸡，外皮香脆、肉质鲜嫩多汁。', '[]', 'meat_dish', 3, 2, 15, 50, 65, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', '杀猪菜', '一道经典的东北菜，以血肠、酸菜和排骨为主料，味道鲜美，营养丰富。', '[]', 'meat_dish', 4, 2, 30, 80, 110, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', '椒盐排条', '椒盐排条是一道经典的本帮菜，外酥里嫩，咸香可口，制作简单。', '[]', 'meat_dish', 4, 2, 30, 15, 45, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', '水煮肉片', '麻辣鲜香、肉片滑嫩的川味经典水煮菜，适合配米饭食用。', '[]', 'meat_dish', 5, 2, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', '洋葱炒猪肉', '咸中带甜，简单上手，一不小心可能让人多吃一碗饭。一般只需 15 分钟即可完成。', '[]', 'meat_dish', 3, 2, 5, 10, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', '烤鸡翅', '外焦里嫩，香辣可口的烤鸡翅，是家庭聚会和朋友小聚时的理想选择。', '[]', 'meat_dish', 3, 2, 40, 40, 80, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', '猪肉烩酸菜', '一道北方名菜，简单易做，富含蛋白质，具有酸菜的特殊风味。', '[]', 'meat_dish', 5, 3, 30, 150, 180, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', '甜辣烤全翅', '使用空气炸锅制作的低油脂甜辣风味鸡全翅，无需成品烧烤酱，食材均为家中常见调料。', '[]', 'meat_dish', 3, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', '番茄红酱', '番茄红酱香浓可口，营养丰富，可以作为薄饼、意面等主食的百搭酱料。适合有烹饪经验的人尝试。', '[]', 'meat_dish', 4, 2, 15, 45, 60, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', '白菜猪肉炖粉条', '这是一道传统的东北家常菜，做法简单、味道上乘，在广大东北人民群众中备受喜爱。', '[]', 'meat_dish', 3, 2, 15, 40, 55, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', '粉蒸肉', '一道经典的中式蒸菜，香味浓郁，口感软糯，营养丰富，适合家庭聚餐或节日宴客。', '[]', 'meat_dish', 4, 2, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('FBllvNtaClPwnbfWr0gQia', '糖醋里脊', '糖醋里脊是中国经典传统名菜之一，以猪里脊肉为主材，配以面粉、淀粉、醋等佐料，酸甜可口，外焦里嫩。', '[]', 'meat_dish', 4, 2, 30, 20, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', '肉饼炖蛋', '肉饼炖蛋是一道传统的中国家常菜，口感鲜嫩，营养丰富，非常适合搭配米饭食用。', '[]', 'meat_dish', 3, 2, 10, 20, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', '腐乳肉', '腐乳肉精选五花肉与红腐乳缠绵共舞。腐乳特有的酒香豆香渗入肉纹，经慢火煨炖化作琥珀色的温柔。入口即化的肉质裹着微甜咸鲜的酱汁，堪称舌尖上的风月宝鉴～', '[]', 'meat_dish', 5, 2, 10, 60, 70, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', '萝卜炖羊排', '萝卜炖羊排是一道常见家常菜，老少皆宜。羊肉鲜美，萝卜清甜，汤汁浓郁。', '[]', 'meat_dish', 4, 2, 30, 120, 150, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', '蒜苔炒肉末', '一道做法简单、味道上乘的北方家常菜。', '[]', 'meat_dish', 2, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('8jSATAz4DCtQoFakselkqy', '虎皮肘子', '虎皮肘子是一道传统名菜，以猪肘为主料，通过先烧再炸后炖三个步骤使肘子皮呈现出虎皮状。肘子皮软烂入味，肥而不腻，瘦肉松软可口。', '[]', 'meat_dish', 5, 4, 120, 300, 420, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', '蚂蚁上树', '一道经典的川菜，以红薯粉丝和肉末为主料，咸香微辣、粉丝软滑爽口、肉末细嫩鲜香。', '[]', 'meat_dish', 3, 2, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', '豉汁排骨', '粤式茶楼经典蒸点，豉香浓郁，排骨滑嫩多汁，超下饭！', '[]', 'meat_dish', 4, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', '辣椒炒肉', '一道以青椒与猪瘦肉为主料，经干煸、腌制、快炒制成的家常湘赣风味热菜。', '[]', 'meat_dish', 3, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', '香干肉丝', '一道经典的家常菜，香干与肉丝的完美结合，口感鲜美，营养丰富。', '[]', 'meat_dish', 3, 2, 15, 10, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', '鱼香肉丝', '经典川菜，咸甜酸辣兼备，以泡椒、葱姜蒜、豆瓣酱炒制里脊肉丝与配菜而成。', '[]', 'meat_dish', 4, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', '麻辣香锅', '一道集多种食材于一锅，麻辣鲜香的川菜经典，适合与朋友共享。', '[]', 'meat_dish', 3, 3, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', '黄焖鸡', '黄焖鸡是一道十分下饭的美食，食材平平无奇又十分容易烹制，一学就会。', '[]', 'meat_dish', 3, 2, 20, 40, 60, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', '黄瓜炒肉', '一道简单易做的家常菜，口感爽脆，肉质鲜嫩。', '[]', 'meat_dish', 3, 2, 15, 7, 22, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', '凉皮', '一道经典的陕西小吃，口感爽滑、酸辣可口，是夏日消暑的佳品。', '[]', 'semi-finished', 3, 2, 20, 10, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', '半成品意面', '简单快捷的半成品意面，适合忙碌的工作日。只需几分钟，即可享受美味的意大利面。', '[]', 'semi-finished', 1, 2, 5, 4, 9, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', '牛油火锅底料', '这是一道正宗的重庆火锅底料，麻辣鲜香，适合家庭自制火锅。', '[]', 'semi-finished', 5, 7, 60, 180, 240, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('ao6tyOztRSEA85STsIxTrM', '速冻水饺', '快速方便地在家里煮出热气腾腾的饺子，适合忙碌时享用。', '[]', 'semi-finished', 1, 1, 5, 12, 17, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', '速冻馄饨', '这道菜简单快捷，适合忙碌的现代生活。通过电饭煲煮制，保留了馄饨皮薄馅嫩、汤清味鲜的特点。', '[]', 'semi-finished', 2, 1, 5, 20, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', '奶油蘑菇汤', '一款口感顺滑、奶香浓郁的西式风味浓汤，制作简单，适合家庭快速料理。', '[]', 'soup', 1, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('gyEity9YJbs5usYWkOClhG', '小米粥', '小米粥是一道营养丰富、易于消化的传统中式粥品，适合各个年龄段的人群食用。', '[]', 'soup', 2, 2, 5, 35, 40, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', '生汆丸子汤', '生汆丸子汤，吃的就是一个鲜、嫩、弹。', '[]', 'soup', 4, 2, 30, 15, 45, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('oLQDeggmNRnxo5YUylCW42', '番茄牛肉蛋花汤', '这道菜色泽鲜艳，口感丰富，酸甜适中，牛肉嫩滑，蛋花细腻，是一道营养丰富的家常汤品。', '[]', 'soup', 3, 2, 20, 15, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', '皮蛋瘦肉粥', '这道皮蛋瘦肉粥口感细腻，营养丰富，是一道经典的中式早餐。', '[]', 'soup', 3, 2, 15, 50, 65, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', '米粥', '大米粥是一道以大米和水作为主要原料经大火煮沸熬制而成的美食，老少皆宜，具有补脾、和胃、清肺功效。', '[]', 'soup', 2, 2, 10, 40, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', '紫菜蛋花汤', '一道简单快捷的家常汤品，以鲜美的紫菜和嫩滑的蛋花为主要食材，口感清淡，营养丰富。', '[]', 'soup', 2, 1, 10, 7, 17, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', '罗宋汤', '罗宋汤是一道源自俄罗斯甜菜汤的汤品，在传入上海后有了本土化的做法。其制作较为简单，初学者只需要2-3小时即可完成。', '[]', 'soup', 4, 4, 30, 300, 330, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', '腊八粥', '腊八粥是一种由多样食材熬制而成的粥，富含碳水化合物、磷镁元素和各类维生素等，不仅补充日常能量，还有养心安神的作用。', '[]', 'soup', 4, 1, 660, 300, 960, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', '西红柿鸡蛋汤', '一道简单易做、营养丰富的家常汤品，酸甜可口，适合各个年龄段的人群。', '[]', 'soup', 2, 2, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('4qgwBig292Eihhc9xD9lQj', '金针菇汤', '一道简单易做的家常汤品，金针菇的鲜美与鸡蛋的嫩滑完美结合，清淡可口。', '[]', 'soup', 2, 2, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', '陈皮排骨汤', '新鲜的排骨搭配广东陈皮、西洋参等药材煲出来的汤非常养生，对脾胃、肺及咽喉都有一定的滋补功效，熬夜党必备。', '[]', 'soup', 4, 2, 30, 300, 330, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', '黄瓜皮蛋汤', '快手家常汤品，清淡中带焦香，暖心暖胃不油腻。', '[]', 'soup', 2, 2, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('zxuIFqiaL2poyEU2iicg66', '可乐炒饭', '可乐炒饭用可乐代替糖分带来焦香微甜的风味。懒人福音，只需简单几步就能做出独特口感的炒饭，香滑鸡蛋配上浓郁酱汁，每一口都是惊喜。', '[]', 'staple', 3, 1, 10, 20, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', '咸肉菜饭', '咸肉菜饭的青菜与咸肉在猪油加持下缠绵共舞，米粒吸饱肉汁染成琥珀色，焦香锅巴与清脆菜梗制造双重口感暴击，挖开就是整个童年的灶披间记忆', '[]', 'staple', 4, 3, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', '手工水饺', '这道菜是一道非常好吃的主食之一，饱肚且易于根据自己口味进行调味，适合在 US 的同学吃不到水饺解馋。', '[]', 'staple', 5, 20, 150, 15, 165, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', '汤面', '汤面是一道简单易做的家常美食，可以根据个人喜好加入各种食材，营养丰富，口感多样。', '[]', 'staple', 2, 2, 15, 20, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('BvobIsCMvJx11q4SJhIqry', '炒年糕', '这道闽南风味的炒年糕是一道非常好吃的主食，制作过程简单，原料获取方便，适合海外朋友满足口腹之欲。', '[]', 'staple', 3, 1, 10, 20, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('DjNC1VVScw0BVHzrwniebT', '炒方便面', '这是一道改良版的炒方便面，通过简单的烹饪技巧让方便面变得更加美味。简单好做，适合快速解决一餐。', '[]', 'staple', 2, 1, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('QUVTjg1TEemQTefJl8abNw', '炒河粉', '一道色香味俱全的经典中式炒面，口感滑嫩，配料丰富。', '[]', 'staple', 4, 2, 20, 15, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', '炒馍', '一道简单美味的家常菜，外酥里嫩，香辣可口。', '[]', 'staple', 3, 2, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', '炸酱面', '一道经典的北京风味面食，以浓郁的酱香和丰富的菜码著称。', '[]', 'staple', 3, 1, 20, 40, 60, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', '热干面', '热干面是武汉的传统小吃，以其独特的碱水面和丰富的调料而闻名。', '[]', 'staple', 3, 1, 15, 5, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', '照烧鸡腿饭', '金黄诱人的照烧鸡腿，淋上甜咸交织的浓郁酱汁，搭配清爽蔬菜与热腾米饭。简单快手却风味十足，一人食的治愈首选～', '[]', 'staple', 4, 1, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', '煮泡面加蛋', '简单快捷的美味主食，适合忙碌或懒人时刻。', '[]', 'staple', 1, 1, 5, 8, 13, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', '猪油拌饭', '猪油拌饭是南方小朋友不爱吃饭时的 fallback，晶莹米粒裹着琥珀色猪油，酱油的咸鲜与葱花的清香在舌尖共舞，每一口都是碳水和脂肪的完美交响曲。', '[]', 'staple', 1, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', '老干妈拌面', '一道简单快捷的家常面食，以老干妈辣椒酱和酱油调味，香辣可口。', '[]', 'staple', 1, 1, 5, 10, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('yLxZNUOIKIazemIiXpMKml', '肉蛋盖饭', '一道简单快捷的单人晚餐，肉香浓郁，鸡蛋嫩滑，搭配米饭非常美味。', '[]', 'staple', 3, 1, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', '葱油拌面', '一道经典的上海家常面点，以香脆葱油酱汁拌面，做法简单，葱香浓郁，适合快速晚餐。', '[]', 'staple', 2, 4, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', '蒸卤面', '豫南经典家常面食，荤素搭配，需两次蒸制与一次卤炒，口感筋道入味。', '[]', 'staple', 4, 2, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', '蛋包饭', '一道日式经典家常菜，由炒饭和嫩滑鸡蛋组成，口感丰富，色香味俱全，富含蛋白质、碳水和维生素，适合早餐或正餐。', '[]', 'staple', 3, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', '蛋炒饭', '经典的家常蛋炒饭，色香味俱全，粒粒分明，口感丰富。', '[]', 'staple', 3, 2, 15, 15, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', '螺蛳粉', '正宗的螺蛳粉是不臭的！这道菜简单易做，味道鲜美，适合家常快速制作。', '[]', 'staple', 1, 1, 5, 15, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', '酸辣蕨根粉', '一道适合初学者的简单易做的凉菜，以酸辣口为主，可做主食。', '[]', 'staple', 2, 2, 5, 10, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', '醪糟小汤圆', '这是一道甜品，以软糯的小汤圆搭配香甜的醪糟，口感丰富，适合冬季暖身。', '[]', 'staple', 2, 2, 5, 10, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', '韭菜盒子', '韭菜盒子是一道美味的传统小吃，外皮酥脆，内馅鲜香，富含维生素和蛋白质。制作简单，适合午餐。', '[]', 'staple', 3, 2, 120, 30, 150, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', '鲜肉烧卖', '以肥瘦3:7猪肉为主馅，加入冬笋、皮冻与香菇，蒸制后皮半透明、馅多汁咸鲜，具江南精致风味。', '[]', 'staple', 4, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', '麻油拌面', '一道简单又美味的懒人菜，适合单身或想要省钱的朋友。只需简单的煮、捞、拌即可完成。', '[]', 'staple', 1, 1, 5, 7, 12, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('Z8gG88Xunen42wXePFCyFE', '麻辣减脂荞麦面', '这道麻辣减脂荞麦面简单易做，美味又健康，适合减脂期间食用。', '[]', 'staple', 2, 1, 5, 15, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', '凉拌油麦菜', '一道清新爽口的凉拌菜，适合夏季食用，口感脆嫩，调味丰富。', '[]', 'vegetable_dish', 1, 2, 10, 5, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', '凉拌豆腐', '一道清爽可口、富含植物蛋白和钙质的低脂家常凉菜，制作简单快捷，适合夏季食用或日常佐餐。', '[]', 'vegetable_dish', 2, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', '凉拌金针菇', '一道简单快捷的开胃凉菜，口感脆嫩爽滑，富含膳食纤维和多种维生素。', '[]', 'vegetable_dish', 2, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', '凉拌黄瓜', '一道简单易做、清爽可口的家常凉菜，适合夏季消暑。', '[]', 'vegetable_dish', 1, 1, 15, NULL, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', '地三鲜', '一道经典的东北家常菜，以茄子、土豆和青椒为主料，口感丰富，营养均衡。', '[]', 'vegetable_dish', 3, 2, 15, 20, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', '家常日本豆腐', '家常日本豆腐用金黄脆壳裹住日本豆腐的娇嫩，三分钟快炒成就餐桌之光，脆嫩咸香暴击味蕾。', '[]', 'vegetable_dish', 3, 2, 15, 10, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', '松仁玉米', '松仁玉米是一道色香味俱全的家常菜，口感甜嫩清爽，松仁香脆，老少皆宜。', '[]', 'vegetable_dish', 2, 2, 10, 10, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', '水油焖蔬菜', '通过加入少量的油和水，提升蔬菜口感并增加脂溶性维生素的摄入，是一道简单又健康的家常菜。', '[]', 'vegetable_dish', 2, 2, 10, 5, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', '油醋爆蛋', '油醋爆蛋是十分简单但是色香味一绝的一道菜，属于湘菜。制作十分简单，大约十分钟。', '[]', 'vegetable_dish', 2, 2, 5, 5, 10, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', '清炒花菜', '清炒花菜是一道常见的家常素菜，富含维生素 C 和膳食纤维，口感脆嫩。做法简单，是一道快速上手的炒菜。', '[]', 'vegetable_dish', 2, 2, 10, 5, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', '清蒸南瓜', '清蒸南瓜是一道制作极其简单的家常甜点或主食。它最大程度地保留了南瓜本身的天然甜味和营养，口感软糯。是健康饮食的不错选择。', '[]', 'vegetable_dish', 1, 2, 5, 20, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', '炒茄子', '一道简单易学的家常菜，口感软糯，味道鲜美。', '[]', 'vegetable_dish', 3, 2, 15, 10, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', '炒青菜', '一道简单快捷的家常菜，保留了青菜的鲜嫩和营养。', '[]', 'vegetable_dish', 2, 1, 5, 5, 10, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', '皮蛋豆腐', '皮蛋豆腐是一道简单易做的菜，松花蛋Q弹滑嫩，配上嫩豆腐的清爽，咸香开胃超下饭！', '[]', 'vegetable_dish', 1, 1, 5, NULL, 5, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('9PQfogADNvSUfUrja9aC3l', '素炒豆角', '巨下饭的家常菜，简单易做，口感鲜美。', '[]', 'vegetable_dish', 2, 2, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', '红烧茄子', '一道经典的家常菜，色泽红亮，口感软糯，味道鲜美。', '[]', 'vegetable_dish', 4, 2, 20, 30, 50, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', '脆皮豆腐', '浓郁的酱汁裹满豆腐，吃一口就停不下来，别提有多好吃。', '[]', 'vegetable_dish', 3, 2, 15, 20, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('oFumXoZEzsGq3lsaO7617m', '茄子炖土豆', '这道菜色泽诱人，口感软糯，是一道家常美味。', '[]', 'vegetable_dish', 3, 2, 15, 30, 45, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', '葱煎豆腐', '一道简单美味的家常菜，外酥里嫩，葱香四溢。', '[]', 'vegetable_dish', 3, 2, 10, 20, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', '蒜蓉西兰花', '一道清淡鲜香、操作简单的家常快手素菜，以蒜香提味，突出西兰花清脆与翠绿。', '[]', 'vegetable_dish', 2, 2, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', '蒲烧茄子', '这道蒲烧茄子色泽诱人，口感软糯，味道鲜美，是一道非常受欢迎的家常菜。', '[]', 'vegetable_dish', 3, 2, 15, 20, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', '蚝油生菜', '一道简单易做、口感爽脆的家常菜，富含维生素，适合各个年龄段的人群。', '[]', 'vegetable_dish', 2, 2, 10, 5, 15, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', '西红柿炒鸡蛋', '西红柿炒蛋是一道简单易学的家常菜，色泽鲜艳、口感丰富，非常适合新手厨师尝试。', '[]', 'vegetable_dish', 2, 2, 10, 10, 20, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', '酸辣土豆丝', '酸辣土豆丝是一道简单易做的家常菜，色泽光亮，酸辣可口。辅料辣椒富含维生素 C。该菜用料简单，好学易做。', '[]', 'vegetable_dish', 2, 2, 15, 7, 22, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('JWSsXj9TxfpReLRg573Om3', '金针菇日本豆腐煲', '金针菇日本豆腐煲是一道容易上手的日常料理，口感鲜美，营养丰富。', '[]', 'vegetable_dish', 2, 2, 10, 20, 30, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', '金钱蛋', '金钱蛋是将水煮蛋切片煎至金黄，配以青红椒、豆豉爆炒而成。外焦里嫩，咸香微辣，形似铜钱寓意吉祥。简单快手又下饭的湘味家常～', '[]', 'vegetable_dish', 3, 2, 15, 20, 35, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', '陕北熬豆角', '陕北熬豆角是一道对初学者极其友善的家常菜，以其独特的熬制方式和丰富的口感而著称。', '[]', 'vegetable_dish', 2, 2, 15, 40, 55, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', '雷椒皮蛋', '这是一道非常简单的下饭凉菜，操作简单且食材常见。虽然成品卖相一般，但却是夏天下饭的神器之一。', '[]', 'vegetable_dish', 2, 2, 10, 15, 25, '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_recipe (recipe_id, name, description, images, category, difficulty, servings, prep_time_minutes, cook_time_minutes, total_time_minutes, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', '鸡蛋火腿炒黄瓜', '一道快手家常小炒，口感清爽微脆，咸香适口，鸡蛋嫩滑、火腿增鲜。', '[]', 'vegetable_dish', 2, 1, NULL, NULL, NULL, '2025-12-28 19:17:19', '2025-12-28 19:17:19');

-- ==================== t_recipe_tag ====================

INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4llgljo9sZn94bpAuM6gyX', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4llgljo9sZn94bpAuM6gyX', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4llgljo9sZn94bpAuM6gyX', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4llgljo9sZn94bpAuM6gyX', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4llgljo9sZn94bpAuM6gyX', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4llgljo9sZn94bpAuM6gyX', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', 'vietnamese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', 'sesame', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I7bMML3zzHX3nZXKS7NfMP', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', 'jiangsu', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('H7j2Q07CevHFBMjU9fqlC3', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', 'smoky', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', 'air_fryer', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rcp0THDXFWhZ0iWJ7TYEJo', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7cxtuNkc1VSXeVPonEXQyC', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', 'jiangsu', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', 'cumin', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', 'spring_fresh', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Og9EsyMJYPDptiLJsShQ2f', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Ip65xzQnsrgHAFZpCh7HsH', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XwuI9CjV2LVtg9nL8q7InU', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 'zhejiang', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 'sweet_sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zHVJejbCkzSEAYKc8YFBbs', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('v3fD6ozOwSKvNLhIFhC5P4', 'vegetarian', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WBI8IHLPu4m5nF0QKnejIl', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0PXxUBY0ZsWJMpFWcyWh14', 'high_protein', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4TMOcPhdbEZKLHDXH62mRx', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kzLPHil1N60srD4j35yMEL', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kzLPHil1N60srD4j35yMEL', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kzLPHil1N60srD4j35yMEL', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kzLPHil1N60srD4j35yMEL', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kzLPHil1N60srD4j35yMEL', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kmX1mciO957s41SmIyzTKj', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kmX1mciO957s41SmIyzTKj', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kmX1mciO957s41SmIyzTKj', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kmX1mciO957s41SmIyzTKj', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('kmX1mciO957s41SmIyzTKj', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I8PfpZh5kzNsbBtZlYCEQq', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('A75ZColUmVyflGhCcVUwBg', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('A75ZColUmVyflGhCcVUwBg', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('A75ZColUmVyflGhCcVUwBg', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('A75ZColUmVyflGhCcVUwBg', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('w8GyOcz3eIFjyqY1nxUL0F', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SEBSUOuPRAM80pXiq56w9Y', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', 'vegetarian', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('afyQukhZhBxjiu1yCgoIHk', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', 'sweet_sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4ENsmGSIrrm02ciYFEyDH2', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6FPkVbSUaFM5tYGbjppNyE', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4W3LTLI4lOVnipgKdF61Aa', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XAoLQh3aDrYiuDeJUyezqB', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('SLRYLwDRHBMNTv8270bnJf', 'air_fryer', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('HadyXz9faXilXk2rtI8ekC', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('HadyXz9faXilXk2rtI8ekC', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('HadyXz9faXilXk2rtI8ekC', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('HadyXz9faXilXk2rtI8ekC', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('HadyXz9faXilXk2rtI8ekC', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('b1VBuMQWEStk52z9Hi9aFf', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2O2mevjfRg3FLuUi0qP5F2', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3gd7xyZ5hvI7P3MEjgF8ET', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TkZk5Yp7gvMgkzua39wAQa', 'vegetarian', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', 'curry', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('R8njUQAhKg8aHYwQy7Ycxb', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', 'smoky', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yW1odkdFoQmDue3Kmmea3y', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('dR4o2q209C79ahYt3XhQYm', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('dR4o2q209C79ahYt3XhQYm', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('dR4o2q209C79ahYt3XhQYm', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('dR4o2q209C79ahYt3XhQYm', 'no_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('pj4DzHAKYIZJ1MGTiiDGOo', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('K6zvXIRbmejiJpilme4YJx', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('K6zvXIRbmejiJpilme4YJx', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('K6zvXIRbmejiJpilme4YJx', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('K6zvXIRbmejiJpilme4YJx', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('K6zvXIRbmejiJpilme4YJx', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('M3H8zF2XUZ2FlVi3h0sTvA', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', 'summer_cool', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('baVPKaRRkUGB2RJIqWcYpr', 'breakfast', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', 'middle_eastern', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('UMmRb1RzoAZ3kXvFnWJkrx', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fCtSjtWXaOibW64SDAtBvy', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('56yPgv2ZADzgaMOSUdXqCR', 'breakfast', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('7e5L8xqWrXbLYouRi8N0Ff', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'middle_eastern', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1mStxkBPI2ET98CxZ3H2qx', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', 'chaozhou', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('I3woiwBE4YPZE0ltwhO4yc', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ljhGcW8WzxtMbtVMF7ANoA', 'microwave', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z3eWrLa4t24XnZHlMZA6Xl', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DOcyLI8aosg02uTeSoA7M1', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', 'zhejiang', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('fanMyjhoUO8LZkRFzS9K8n', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8jSATAz4DCtQoFakselkqy', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8jSATAz4DCtQoFakselkqy', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8jSATAz4DCtQoFakselkqy', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8jSATAz4DCtQoFakselkqy', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8jSATAz4DCtQoFakselkqy', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8jSATAz4DCtQoFakselkqy', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', 'cantonese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('GwVNrLB3XNLsGjLrWkX7MA', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', 'bitter', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cLASPsuC6FJEmUJLcFqMyL', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 'hunan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', 'american', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6X3YkDcPAiwNLvrdzqI23k', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yMq7v8xmqsxW1JFQlNV8Wt', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KeACat4a0Ycb4FvnuybNG', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PnXSwmzyF8IZ48Y27yoTdD', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', 'dongbei', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('37jLPV5JefXrr4vsI1r0sK', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('xmiOeSioiSLBwcZ6JMYCEx', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 'cantonese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 'cumin', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', 'summer_cool', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EZf5olwznwQX6Rnbq3dMTY', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('2TdbPEWosACjPHZSjMq5yY', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 'slow_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FBllvNtaClPwnbfWr0gQia', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FBllvNtaClPwnbfWr0gQia', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FBllvNtaClPwnbfWr0gQia', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FBllvNtaClPwnbfWr0gQia', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FBllvNtaClPwnbfWr0gQia', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', 'vinegar', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bsVFYRCJYub6r2n9JVBVpQ', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z9l0TcOPma9S43Vrzjud5N', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', 'dongbei', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', 'bitter', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('0rd0ElNzk9jQ1lPSoUyraD', 'vegetarian', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', 'hunan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Y5tNfPJr4ZriE5wNU0m7IM', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', 'spanish', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TuhT4ZpgObb4e9nf9wOBQp', 'slow_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oM16wT3cZmCLmkWbRGLhIE', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('85g5oUxPq2CWXmDETiuOnA', 'beginner', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cDobtnqaJQdNObSnjl7uH9', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', 'curry', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1LwioNB1bb4C8oHgwEO49y', 'vegetarian', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 'sweet_sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 'no_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', 'smoky', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lAq7KME8YL9vHyeRdinh7x', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', 'dongbei', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3KzuGxNyq8Zrfof4M7EppC', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qVJANVrCZxopxQg6vgBb8j', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z4DnrchAd17fcyOePFCpbf', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p7MAVXCgBqIGGeMqA15HP7', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', 'american', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('g82H2WY09YkUS4PhrMvtFx', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OacdhYNMJMI53ynRvCsh9Z', 'no_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', 'bitter', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('WHtomsdZmNYj1YPezqSZSZ', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ao6tyOztRSEA85STsIxTrM', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ao6tyOztRSEA85STsIxTrM', 'wine', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ao6tyOztRSEA85STsIxTrM', 'smoky', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ao6tyOztRSEA85STsIxTrM', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ao6tyOztRSEA85STsIxTrM', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', 'american', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Tnnr5cwpw2jMpY0sjpFAS1', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', 'late_night', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rq2x1iHxVweAsAPBMULQXZ', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', 'cantonese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', 'spring_fresh', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('1foo36wy8vYnNVcFhCwGkH', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OLwZMEEK4egV9vXNUM3HG1', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('lgsrTbt3WwGBq9mgUIbbyE', 'beginner', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('S8wNJtw5726nZk0nDhqRUd', 'beginner', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Gj108A79IZZuwXVKCf1fuI', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oLQDeggmNRnxo5YUylCW42', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oLQDeggmNRnxo5YUylCW42', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oLQDeggmNRnxo5YUylCW42', 'spring_fresh', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oLQDeggmNRnxo5YUylCW42', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oLQDeggmNRnxo5YUylCW42', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4qgwBig292Eihhc9xD9lQj', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4qgwBig292Eihhc9xD9lQj', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4qgwBig292Eihhc9xD9lQj', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4qgwBig292Eihhc9xD9lQj', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('4qgwBig292Eihhc9xD9lQj', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('qRV5nI3NaW5OXmTK5p0foI', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', 'italian', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QEIR2M4Yx9STlMS7BJ9cSI', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gyEity9YJbs5usYWkOClhG', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gyEity9YJbs5usYWkOClhG', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gyEity9YJbs5usYWkOClhG', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gyEity9YJbs5usYWkOClhG', 'beginner', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gyEity9YJbs5usYWkOClhG', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', 'cantonese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EkrYb2I7w2pNRh1KIiUe9j', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KhqppAi6wq0SJXIufN7o7f', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BvobIsCMvJx11q4SJhIqry', 'fujian', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BvobIsCMvJx11q4SJhIqry', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BvobIsCMvJx11q4SJhIqry', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BvobIsCMvJx11q4SJhIqry', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BvobIsCMvJx11q4SJhIqry', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BvobIsCMvJx11q4SJhIqry', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('TVhdKDeR3a3a69XPQ5hC7d', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', 'rainy_comfort', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FPvRQiJ2fmllAiOAuzeToo', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', 'vinegar', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('66pqGD6D2cIVfJg3WmAKAj', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', 'cumin', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('egBykH5NBt0XSPSKMUpNxo', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cY0eI9wrmP0LdabMk0j6Sq', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('D7A8t66w8F3HQEKQzd79AO', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yLxZNUOIKIazemIiXpMKml', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yLxZNUOIKIazemIiXpMKml', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yLxZNUOIKIazemIiXpMKml', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yLxZNUOIKIazemIiXpMKml', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('yLxZNUOIKIazemIiXpMKml', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', 'bitter', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bNFLahw70jtfmBkPMt7qWw', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 'korean', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', 'vinegar', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('jmgNh1DyPrkoVWTMpPvMfT', 'no_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('cNp0IOSzIvZOGpR5VvVClr', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QUVTjg1TEemQTefJl8abNw', 'cantonese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QUVTjg1TEemQTefJl8abNw', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QUVTjg1TEemQTefJl8abNw', 'curry', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QUVTjg1TEemQTefJl8abNw', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QUVTjg1TEemQTefJl8abNw', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QUVTjg1TEemQTefJl8abNw', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('KEpE0f2AkjorCW6VmAaL0g', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', 'curry', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('94dly9SOQdn3eYH7kAdMrZ', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gzw6pJNEY5UXqrMjOeziTQ', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', 'bitter', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('bTRUTLGno6reUGPr9O36Mh', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8MpHhyNvCn3xsLjhF1ZFPk', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('O6gvFpJonEKyY0mDJTTtre', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', 'korean', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('U0n3JIx4Ou4AEyF7hLRQD8', 'no_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z8gG88Xunen42wXePFCyFE', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z8gG88Xunen42wXePFCyFE', 'spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z8gG88Xunen42wXePFCyFE', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z8gG88Xunen42wXePFCyFE', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z8gG88Xunen42wXePFCyFE', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('Z8gG88Xunen42wXePFCyFE', 'high_protein', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 'jiangsu', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 'lunch_box', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zxuIFqiaL2poyEU2iicg66', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zxuIFqiaL2poyEU2iicg66', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zxuIFqiaL2poyEU2iicg66', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zxuIFqiaL2poyEU2iicg66', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zxuIFqiaL2poyEU2iicg66', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', 'picnic', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('tcHBRWKIKXMldECgi6e7vd', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DjNC1VVScw0BVHzrwniebT', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DjNC1VVScw0BVHzrwniebT', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('DjNC1VVScw0BVHzrwniebT', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('8Q0Hzc2HKnAwzxXKuyhgil', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', 'korean', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hcxK9liQGBqv7sv4QlNiwX', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('3VZerxG69xB8MKYrVfnjWO', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', 'wine', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QTEj8k2l6RF9YlyYrav9g1', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('rFsoNckGhu0K7y6i7zMurz', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', 'hunan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', 'wine', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('PsQLmSvGXyaPBn5MBZevMU', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', 'cantonese', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gsTdq9ggWql86xJyPRYO3U', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9PQfogADNvSUfUrja9aC3l', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9PQfogADNvSUfUrja9aC3l', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9PQfogADNvSUfUrja9aC3l', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9PQfogADNvSUfUrja9aC3l', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9PQfogADNvSUfUrja9aC3l', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('9PQfogADNvSUfUrja9aC3l', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', 'wine', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('5zNRuuLigSxLl4UbgTjFR4', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('QXSlDZHAgvqEEBBAsp6nRr', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', 'shanghai', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('p2oHri6YesXLSMFMK7VVt3', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('VEv1rkpRIigyCqb8KhbMkc', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('u8R1sdJuG0pywQCFFVDmZk', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', 'sichuan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', 'mild_spicy', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', 'savory', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('gftRjjHVkwMyaeQzQYe2ah', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', 'northwest', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('ZEpMDvpb2zhvvPVAliXbhx', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oFumXoZEzsGq3lsaO7617m', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oFumXoZEzsGq3lsaO7617m', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oFumXoZEzsGq3lsaO7617m', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oFumXoZEzsGq3lsaO7617m', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('oFumXoZEzsGq3lsaO7617m', 'kids_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('J64GEpYlJMEQ6UfKBJ5N2q', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('MF6st5bxjLXOrw0raUj397', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('MF6st5bxjLXOrw0raUj397', 'wine', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('MF6st5bxjLXOrw0raUj397', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('MF6st5bxjLXOrw0raUj397', 'comfort_food', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('MF6st5bxjLXOrw0raUj397', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', 'ginger', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('hHvrACv7iA4YEVhD7PGqfD', 'no_cook', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('JWSsXj9TxfpReLRg573Om3', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('JWSsXj9TxfpReLRg573Om3', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('JWSsXj9TxfpReLRg573Om3', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('JWSsXj9TxfpReLRg573Om3', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('JWSsXj9TxfpReLRg573Om3', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 'hangover', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', 'vinegar', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', 'winter_warm', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('vuj8XAePvKYuPSUnY7ZA5a', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', 'beijing', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('NLK3nj5wczSUsB3N9KCNe3', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', 'dongbei', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('zYRE52sHRyQLmfHTuZQHfL', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', 'hunan', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', 'light', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', 'sweet_sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', 'nourishing', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('E7mIfYYbAH3SRqLYv6i1ZM', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', 'sweet', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', 'scallion', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', 'party', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', 'low_fat', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('BYCECsLilRLvkP2EIMgbjF', 'one_pot', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', 'shandong', 'cuisine', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', 'sour', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', 'garlic', 'flavor', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', 'quick_meal', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', 'elderly_friendly', 'scene', '2025-12-28 19:17:19');
INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES ('XnwjLYUfSWFdDcLh2euc5e', 'one_pot', 'scene', '2025-12-28 19:17:19');

-- ==================== t_refresh_token ====================
-- 注意：refresh_token 存储在 Redis 中，不需要数据库表，此部分已移除

-- ==================== t_step ====================

INSERT INTO t_step VALUES (1, 'I7bMML3zzHX3nZXKS7NfMP', 1, '将肉蟹掀盖后对半砍开，蟹钳用刀背轻轻拍裂。切口和蟹钳蘸一下生粉，不要太多。撒5g生粉到蟹盖中，盖住蟹黄，备用。

💡 提示：生粉用量要适量，过多会影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (2, 'I7bMML3zzHX3nZXKS7NfMP', 2, '洋葱切成洋葱碎，大蒜切碎，备用。

💡 提示：洋葱和大蒜切得越细越好，这样更容易出香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (3, 'I7bMML3zzHX3nZXKS7NfMP', 3, '烧一壶开水，约500ml，备用。

💡 提示：开水用于后续的焖煮步骤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (4, 'I7bMML3zzHX3nZXKS7NfMP', 4, '起锅烧油，倒入约20ml食用油，等待10秒让油温升高。

💡 提示：油温不宜过高，以免煎糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (5, 'I7bMML3zzHX3nZXKS7NfMP', 5, '将螃蟹切口朝下，轻轻放入锅中，煎20秒，这一步主要是封住蟹黄和蟹肉。然后翻面，每面煎10秒。煎完将螃蟹取出备用。

💡 提示：煎的时候要小心，避免蟹黄流出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (6, 'I7bMML3zzHX3nZXKS7NfMP', 6, '将螃蟹盖放入锅中，使用勺子舀起锅中热油泼到蟹盖中，煎封住蟹盖中的蟹黄，煎20秒后取出备用。

💡 提示：注意控制油温，防止溅油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (7, 'I7bMML3zzHX3nZXKS7NfMP', 7, '不用刷锅，再倒入10ml食用油，大火让油温升高至轻微冒烟，将大蒜末，洋葱碎倒入，炒10秒钟。

💡 提示：快速翻炒，使洋葱和大蒜出香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (8, 'I7bMML3zzHX3nZXKS7NfMP', 8, '将咖喱块放入锅中炒化（10秒），放入煎好的螃蟹，翻炒均匀。

💡 提示：咖喱块要完全融化，与螃蟹充分混合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (9, 'I7bMML3zzHX3nZXKS7NfMP', 9, '倒入开水300ml，焖煮3分钟。

💡 提示：保持中小火，让咖喱味充分渗入螃蟹', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (10, 'I7bMML3zzHX3nZXKS7NfMP', 10, '焖煮完后，倒入椰浆和蛋清，关火，不断翻炒，一直到酱汁变浓稠，至酱汁挂勺。

💡 提示：关火后继续翻炒，防止蛋清凝固成块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (11, 'I7bMML3zzHX3nZXKS7NfMP', 11, '出锅装盘。

💡 提示：可以撒上一些葱花或香菜提味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (12, 'H7j2Q07CevHFBMjU9fqlC3', 1, '将鳝鱼切成三段后切成细丝，加入0.5g胡椒粉、3g料酒搅拌均匀，再加入5g香油腌制10分钟。

💡 提示：鳝鱼不要洗得太干净，保留一些血水可以避免发黑发臭。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (13, 'H7j2Q07CevHFBMjU9fqlC3', 2, '热锅冷油，将锅烧热后倒入适量植物油，烧至6成热（约180℃）。

💡 提示：热油滑锅可以防止食材粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (14, 'H7j2Q07CevHFBMjU9fqlC3', 3, '加入一半的蒜末（40g）和全部姜末（20g），翻炒几下出香味。

💡 提示：蒜末和姜末要快速翻炒，以免炒焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (15, 'H7j2Q07CevHFBMjU9fqlC3', 4, '加入腌制好的鳝丝，中火爆炒30秒。

💡 提示：中火快炒可以使鳝丝保持嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (16, 'H7j2Q07CevHFBMjU9fqlC3', 5, '边缘淋入10g料酒，翻炒几下去腥。

💡 提示：料酒可以去除鳝丝的腥味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (17, 'H7j2Q07CevHFBMjU9fqlC3', 6, '加入生抽（3g）、蚝油（2g）、老抽（2g），翻炒几下使鳝丝上色。

💡 提示：调料要均匀地裹在鳝丝上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (18, 'H7j2Q07CevHFBMjU9fqlC3', 7, '加入食用盐（2g）、白糖（10g）、3g胡椒粉，炒匀。

💡 提示：根据个人口味调整糖和盐的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (19, 'H7j2Q07CevHFBMjU9fqlC3', 8, '将淀粉（10g）和水（50g）混合成水淀粉，倒入锅中，收汁至浓稠。

💡 提示：勾芡时要边倒边快速翻炒，防止结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (20, 'H7j2Q07CevHFBMjU9fqlC3', 9, '装盘，撒上剩余的蒜末（40g）和葱花（15g）。

💡 提示：蒜末和葱花可以增加菜品的香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (21, 'H7j2Q07CevHFBMjU9fqlC3', 10, '另起锅烧热，加入猪油（20g），烧至七成热（约210℃），浇在鳝丝上。

💡 提示：热油浇在蒜末和葱花上会发出“滋滋”声，香气四溢。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (22, 'rcp0THDXFWhZ0iWJ7TYEJo', 1, '将黑鳕鱼片分别放入密封袋中，鱼皮向下放在盘子中。

💡 提示：确保鱼片平整，便于均匀加热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (23, 'rcp0THDXFWhZ0iWJ7TYEJo', 2, '取葱白切丝25g，姜去皮后切丝10g，混合在一起后分成两半，分别放在袋内鱼片上。

💡 提示：葱白和姜丝要均匀铺在鱼片上，以增加香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (24, 'rcp0THDXFWhZ0iWJ7TYEJo', 3, '每个袋子倒入2.5mL料酒。

💡 提示：料酒可以去腥增香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (25, 'rcp0THDXFWhZ0iWJ7TYEJo', 4, '封好密封袋，放入微波炉中，中火（800瓦）微波至鱼肉不透明且容易散开时（约3.5-5分钟），从袋中取出鱼片。

💡 提示：根据鱼片厚度调整时间，可以用筷子轻轻插入鱼肉检查是否熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (26, 'rcp0THDXFWhZ0iWJ7TYEJo', 5, '去除青葱和姜。

💡 提示：去掉葱姜可以让鱼肉更加清爽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (27, 'rcp0THDXFWhZ0iWJ7TYEJo', 6, '取酱油25mL，芝麻油2mL，混合均匀后平均淋在两片鱼片上。

💡 提示：酱油和芝麻油的混合液可以提升鱼肉的风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (28, 'rcp0THDXFWhZ0iWJ7TYEJo', 7, '取葱绿切细丝10g，姜去皮后切丝3g，混合后分成两份撒在鱼片上。

💡 提示：葱绿和姜丝可以增加菜品的色彩和口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (29, 'rcp0THDXFWhZ0iWJ7TYEJo', 8, '取花生油50mL，在小锅中加热至190℃。

💡 提示：油温要足够高，以便激发出葱姜的香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (30, 'rcp0THDXFWhZ0iWJ7TYEJo', 9, '将热油淋到放有葱绿的鱼片上，立刻上桌。

💡 提示：热油淋上去会发出“滋滋”声，增添香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (31, 'Ip65xzQnsrgHAFZpCh7HsH', 1, '将巴沙鱼从冷冻柜取出，室温自然解冻约5小时。

💡 提示：确保鱼完全解冻，否则影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (32, 'Ip65xzQnsrgHAFZpCh7HsH', 2, '将解冻后的巴沙鱼切成薄片，约5cm长，3cm宽。

💡 提示：切片时刀要锋利，保持鱼片均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (33, 'Ip65xzQnsrgHAFZpCh7HsH', 3, '将切好的鱼片放入大不锈钢碗中，加入30g红油豆瓣酱、3g盐、10ml藤椒油、3g白胡椒粉，用手抓匀后加入5ml菜籽油封住口味。

💡 提示：腌制时不要用力过猛，以免鱼片碎裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (34, 'Ip65xzQnsrgHAFZpCh7HsH', 4, '将腌制好的鱼片静置至少30分钟入味。

💡 提示：腌制时间越长，味道越入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (35, 'Ip65xzQnsrgHAFZpCh7HsH', 5, '将花菜洗净切成小朵，生菜洗净备用。

💡 提示：蔬菜要洗净，去除杂质。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (36, 'Ip65xzQnsrgHAFZpCh7HsH', 6, '将花菜放入开水锅中焯水2-3分钟，捞出沥干水分；生菜可以稍微焯水或直接炒熟。

💡 提示：焯水时间不宜过长，以免蔬菜变软。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (37, 'Ip65xzQnsrgHAFZpCh7HsH', 7, '热锅冷油（20ml菜籽油），加入10g红油豆瓣酱、10g豆豉（可选）和蒜末，中火慢炒至香味四溢。

💡 提示：炒豆瓣酱时火候不宜过大，以免糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (38, 'Ip65xzQnsrgHAFZpCh7HsH', 8, '加入150ml热水，待水沸腾后加入腌制好的鱼片，轻轻翻动让鱼片散开，加入2g盐和2g糖调味，水再次沸腾后煮约2-3分钟即可。

💡 提示：鱼片易熟，煮的时间不宜过长，以免鱼片变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (39, 'Ip65xzQnsrgHAFZpCh7HsH', 9, '将焯水后的花菜和炒熟的生菜铺在大碗底部，然后将煮好的鱼片连同汤汁一起倒入碗中。

💡 提示：先放蔬菜再放鱼片，使菜品层次分明。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (40, '7cxtuNkc1VSXeVPonEXQyC', 1, '将生蚝用刷子或牙刷彻底清洗干净，去除表面的泥沙。

💡 提示：确保生蚝表面无杂质，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (41, '7cxtuNkc1VSXeVPonEXQyC', 2, '在蒸锅中加入足够的水（约1升），大火烧开后，将蒸屉放入蒸锅中。

💡 提示：水开后再放蒸屉，保证蒸汽充足。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (42, '7cxtuNkc1VSXeVPonEXQyC', 3, '将洗净的生蚝平铺在蒸屉上，盖上锅盖，大火蒸3分钟。

💡 提示：蒸的时间不宜过长，以免肉质变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (43, '7cxtuNkc1VSXeVPonEXQyC', 4, '用湿抹布掀开锅盖，小心地将每个生蚝的外壳打开，去掉一半的壳，保留有肉的一半。将生蚝肉面朝上放置，每个生蚝上放一根姜丝和约5g蒜末。

💡 提示：操作时要小心，避免烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (44, '7cxtuNkc1VSXeVPonEXQyC', 5, '重新盖上锅盖，继续大火蒸3.5分钟。

💡 提示：保持大火，确保生蚝熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (45, '7cxtuNkc1VSXeVPonEXQyC', 6, '停火后，用湿抹布掀开锅盖，每个生蚝上淋上5ml酱油。

💡 提示：酱油可以提鲜，但不要过多，以免掩盖生蚝的鲜味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (46, '7cxtuNkc1VSXeVPonEXQyC', 7, '将蒸好的生蚝盛盘，撒上葱花即可上桌。

💡 提示：趁热食用，味道更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (47, 'zHVJejbCkzSEAYKc8YFBbs', 1, '将鲫鱼去鳞、去内脏、洗净，用厨房纸巾擦干水分。在鱼身两侧各划3-4刀，深度约为鱼肉厚度的1/3。

💡 提示：划花刀有助于鱼肉更好地入味和成熟', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (48, 'zHVJejbCkzSEAYKc8YFBbs', 2, '将姜切丝，蒜瓣拍碎或切片，干辣椒切碎备用。

💡 提示：姜蒜和干辣椒可以提前准备好，方便后续操作', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (49, 'zHVJejbCkzSEAYKc8YFBbs', 3, '锅中加入50ml油，开中小火加热至油温五成热（约150℃），放入擦干水分的鱼，小火慢煎。

💡 提示：煎鱼时不要急于翻动，待一面煎至金黄再翻面', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (50, 'zHVJejbCkzSEAYKc8YFBbs', 4, '将鱼翻面，继续小火慢煎至另一面也呈金黄色。

💡 提示：煎鱼时可以用铲子轻轻按压鱼身，使其受热均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (51, 'zHVJejbCkzSEAYKc8YFBbs', 5, '将煎好的鱼推到锅边，放入姜丝、蒜瓣和干辣椒，翻炒出香味。

💡 提示：炒香调料时注意火候，避免糊锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (52, 'zHVJejbCkzSEAYKc8YFBbs', 6, '倒入30ml料酒，沿锅边淋入，盖上锅盖焖煮1分钟，让酒精挥发。

💡 提示：料酒可以去腥增香，但要注意安全，避免溅油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (53, 'zHVJejbCkzSEAYKc8YFBbs', 7, '加入5ml醋、10g白砂糖和15ml酱油，翻炒均匀。

💡 提示：调味料要均匀分布在鱼身上', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (54, 'zHVJejbCkzSEAYKc8YFBbs', 8, '加入足够的冷水，以刚好淹没鱼身为宜，调成中火，盖上锅盖炖煮。

💡 提示：炖煮过程中可以适当翻动鱼身，使其均匀受热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (55, 'zHVJejbCkzSEAYKc8YFBbs', 9, '10分钟后，加入10g盐、小米椒、蚝油和味精，继续炖煮。

💡 提示：调味品可以根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (56, 'zHVJejbCkzSEAYKc8YFBbs', 10, '当锅内汤汁收至鱼脊背线上的鱼鳍下方一点点时，转小火，撒上葱花和香菜，盖上锅盖焖20秒，关火。

💡 提示：收汁时注意观察，避免烧焦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (57, 'zHVJejbCkzSEAYKc8YFBbs', 11, '将红烧鱼盛出，装盘即可。

💡 提示：装盘时可以将锅中的汤汁浇在鱼身上，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (58, '4llgljo9sZn94bpAuM6gyX', 1, '将鱼头去鳞，清洗鱼头处未被清理干净的内脏。剁去鱼鳍、清理鱼鳃。将鱼头下巴与鱼身连接的地方剁开，鱼身剁块，鱼头剁成四/六瓣。

💡 提示：处理鱼头时要小心，可以参考相关视频学习具体操作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (59, '4llgljo9sZn94bpAuM6gyX', 2, '将剁好的鱼头进行清洗，最好洗掉鱼块上滞留的血水。

💡 提示：彻底清洗可以去除腥味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (60, '4llgljo9sZn94bpAuM6gyX', 3, '将清洗好的鱼块放入盆中，加入5g盐、10g生抽、10g料酒。放入葱（前半段切碎的那个）、1/3姜片。将其拌匀，静置1.5小时。

💡 提示：腌制时间不宜过长，以免鱼肉变质。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (61, '4llgljo9sZn94bpAuM6gyX', 4, '准备其他食材：大葱切两半，后半段大葱（葱白处）切段，每段长度约4cm；前半段（葱叶处）先切段，再将每段劈为四瓣。姜切片，每片厚度约3mm。大蒜拍碎。拿出两棵香菜去根，切为1.5cm香菜碎。将美人椒切为厚度为3mm的辣椒圈。干辣椒切四段。

💡 提示：提前准备好所有食材，方便后续操作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (62, '4llgljo9sZn94bpAuM6gyX', 5, '锅中加入30ml油，等待油面微冒青烟时，将锅关至小火。

💡 提示：油温适中，避免食材糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (63, '4llgljo9sZn94bpAuM6gyX', 6, '放入姜片，慢慢翻炒，以姜片中的大部分汁水被炒出，以金黄色为准。

💡 提示：姜片炒至金黄可以增加香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (64, '4llgljo9sZn94bpAuM6gyX', 7, '放入葱段，翻炒至葱段略显发白。

💡 提示：葱段炒至略显发白可以提升香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (65, '4llgljo9sZn94bpAuM6gyX', 8, '放入蒜碎、八角、干辣椒，翻炒5秒。

💡 提示：快速翻炒，避免蒜碎炒焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (66, '4llgljo9sZn94bpAuM6gyX', 9, '将腌制好的鱼头倒入锅中，翻炒2-3分钟。

💡 提示：翻炒均匀，使鱼头表面略微煎黄。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (67, '4llgljo9sZn94bpAuM6gyX', 10, '倒入500ml清水，加入2g盐、3g鸡精、5g生抽、3g老抽、5g料酒、2g黑胡椒粉、3g陈醋。将两棵香菜放入锅中，盖上锅盖。

💡 提示：调味料要均匀撒入锅中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (68, '4llgljo9sZn94bpAuM6gyX', 11, '调至大火，将水烧开。

💡 提示：大火烧开可以迅速煮沸。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (69, '4llgljo9sZn94bpAuM6gyX', 12, '调至中火，慢焖入味。

💡 提示：中火慢炖可以使鱼头更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (70, '4llgljo9sZn94bpAuM6gyX', 13, '当汤汁减少一半时，打开锅盖。

💡 提示：注意观察汤汁的状态，避免烧干。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (71, '4llgljo9sZn94bpAuM6gyX', 14, '调至大火收汁，汤汁剩余1/3时，关火盛至小盆中。

💡 提示：大火收汁可以使汤汁更加浓郁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (72, '4llgljo9sZn94bpAuM6gyX', 15, '将香菜放至已经盛出的鱼头上，把切好的美人椒圈放在香菜之上。

💡 提示：装饰可以提升菜品的美观度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (73, 'XwuI9CjV2LVtg9nL8q7InU', 1, '将鲤鱼清洗干净，在鱼背肉厚处拉几道斜口，方便入味。

💡 提示：斜口要均匀，不要切得太深。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (74, 'XwuI9CjV2LVtg9nL8q7InU', 2, '大葱、姜、蒜、干辣椒分别清洗干净。葱白处切段，每段长度约4cm，再将每段劈为四瓣；姜切片，每片厚度约3mm；一个大蒜拍碎切末，其余蒜切为二瓣；干辣椒切四段。

💡 提示：切好的葱、姜、蒜和干辣椒备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (75, 'XwuI9CjV2LVtg9nL8q7InU', 3, '五花肉切片，约4cm*4cm。

💡 提示：五花肉切片要薄一些，更容易煸出香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (76, 'XwuI9CjV2LVtg9nL8q7InU', 4, '锅里多倒点油，烧至7成热（刚刚开始冒烟），下入鱼炸1分钟至鱼皮稍稍变硬捞出备用（注意不要一下锅就拨弄鱼，等炸一会再拨弄、翻面）。炸鱼的油倒出，锅里留一点底油。

💡 提示：炸鱼时火候要控制好，防止外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (77, 'XwuI9CjV2LVtg9nL8q7InU', 5, '将锅里底油烧热，下入五花肉，煸出香味。

💡 提示：五花肉煸至金黄，出油即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (78, 'XwuI9CjV2LVtg9nL8q7InU', 6, '放入干辣椒、葱、姜、蒜瓣，翻炒1分钟。

💡 提示：翻炒均匀，使调料充分释放香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (79, 'XwuI9CjV2LVtg9nL8q7InU', 7, '将炸好的鱼倒入锅中。沿锅边依次倒入50ml料酒、50ml陈醋、50ml生抽、20ml老抽、5ml蚝油、1茶匙盐、50g白糖，然后加入清水没过鱼面。

💡 提示：调料要沿着锅边倒入，这样可以使调料更好地渗透到鱼肉中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (80, 'XwuI9CjV2LVtg9nL8q7InU', 8, '调至中火，将水烧开后，调至小火，慢焖入味，加盖焖煮15分钟。

💡 提示：加盖焖煮可以更好地锁住香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (81, 'XwuI9CjV2LVtg9nL8q7InU', 9, '打开锅盖，挑出锅里的葱、姜、蒜、干辣椒。

💡 提示：挑出调料是为了保持菜品的美观。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (82, 'XwuI9CjV2LVtg9nL8q7InU', 10, '调至大火收汁，汤汁剩余1/4时，撒点蒜末，关火盛出。

💡 提示：收汁时要注意火候，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (83, 'zwbr6EzZalrBrxzzyXh5TF', 1, '处理螃蟹：冷冻20分钟使其昏迷（勿冻硬），或用筷子从口器插入破坏神经；彻底清洗后去除蟹胃（三角包）、蟹腮、蟹心（六角形白片）；切成50–80 g块，均匀裹薄层淀粉，用厨房纸擦干表面水分

💡 提示：死蟹禁用（除正规冷冻品外）；半解冻蟹更易操作且减少掉腿、肉质流失', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (84, 'zwbr6EzZalrBrxzzyXh5TF', 2, '油炸螃蟹：锅中倒入约500 ml食用油，烧至180 °C（若灶具功率小，预热至200 °C），分批下蟹块炸1分钟（冷冻蟹延长至2分钟），至表面定型微黄，捞出沥油

💡 提示：务必擦干再下锅，防油溅；分批炸避免油温骤降', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (85, 'zwbr6EzZalrBrxzzyXh5TF', 3, '爆香底料：锅中放30–50 ml食用油（+10 ml若加虾），中小火爆香蒜片、姜片、干辣椒段

💡 提示：火候控制在中小火，避免焦糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (86, 'zwbr6EzZalrBrxzzyXh5TF', 4, '炒酱：加入蚝油、海鲜酱、黄豆酱、甜面酱、番茄酱和冰糖，小火持续翻炒至红油析出、酱香浓郁

💡 提示：全程小火，不停搅拌防糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (87, 'zwbr6EzZalrBrxzzyXh5TF', 5, '炖煮主料：倒入炸好的蟹块、土豆块、啤酒和清水，大火烧开后转小火加盖焖炖12分钟

💡 提示：确保液体没过食材2/3；若加虾，此时同步下锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (88, 'zwbr6EzZalrBrxzzyXh5TF', 6, '加入配菜：掀盖放入年糕片（铺于表面）、青椒片、红椒片、洋葱瓣，转大火收汁

💡 提示：年糕沉底易糊，务必先铺表面；收汁至汤汁浓稠、能均匀附着在食材表面', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('zwbr6EzZalrBrxzzyXh5TF', 7, '调味出锅：撒入鸡精、白胡椒粉，翻匀，关火', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (90, 'Og9EsyMJYPDptiLJsShQ2f', 1, '将螃蟹刷洗干净，去掉腮、胃、心等不可食用部分，然后在砧板上对半劈开。

💡 提示：处理螃蟹时要小心，以免被夹伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (91, 'Og9EsyMJYPDptiLJsShQ2f', 2, '锅里下菜油，放入姜末和豆瓣酱爆香，加入冰糖炒化，直到冒小气泡后盛出备用。

💡 提示：火候不宜过大，以免炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (92, 'Og9EsyMJYPDptiLJsShQ2f', 3, '在盘子里铺上一层炒好的酱料，然后把切好的螃蟹切开面朝下，整齐排放在酱上。

💡 提示：螃蟹切开面朝下可以更好地吸收酱汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (93, 'Og9EsyMJYPDptiLJsShQ2f', 4, '放点葱段和姜片，建议敲个鸡蛋或在盘底铺肉末。

💡 提示：鸡蛋和肉末可以增加菜肴的丰富度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (94, 'Og9EsyMJYPDptiLJsShQ2f', 5, '将盘子放入蒸锅中，大火蒸10-12分钟。

💡 提示：蒸制时间根据螃蟹大小适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (95, 'Og9EsyMJYPDptiLJsShQ2f', 6, '另起一锅，倒入500ml水，加入剩余的酱料，烧开后转小火炖煮10分钟。

💡 提示：炖煮过程中可以适当搅拌，使酱料更加均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (96, 'Og9EsyMJYPDptiLJsShQ2f', 7, '将蒸好的螃蟹取出，淋上炖好的酱汁，撒上葱花即可。

💡 提示：出锅后再撒上一点葱花会更香也更好看。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (97, '4W3LTLI4lOVnipgKdF61Aa', 1, '将两片吐司放入面包机中。

💡 提示：确保吐司平整放置，避免烘烤不均。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (98, '4W3LTLI4lOVnipgKdF61Aa', 2, '设置面包机至烘烤模式，选择适当的档位（如：中档），启动面包机。

💡 提示：根据面包机的具体型号和功能，选择合适的烘烤档位。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (99, '4W3LTLI4lOVnipgKdF61Aa', 3, '等待面包机自动弹出加热完成的吐司。

💡 提示：注意观察吐司的颜色，避免过度烘烤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (100, '4W3LTLI4lOVnipgKdF61Aa', 4, '取出一片吐司，用刀或勺子均匀涂抹一层果酱（约1汤匙）。

💡 提示：涂抹时尽量均匀，避免果酱过多导致溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (101, '4W3LTLI4lOVnipgKdF61Aa', 5, '将另一片吐司盖在涂有果酱的吐司上，轻轻按压使其贴合。

💡 提示：按压时力度要适中，以免破坏吐司的完整性。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (102, 'HadyXz9faXilXk2rtI8ekC', 1, '准备一个小碗，倒入5毫升油，撒上1克盐，搅拌均匀。倾斜碗使油沾在碗表面。

💡 提示：确保碗内壁均匀涂抹一层油，防止鸡蛋粘连', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (103, 'HadyXz9faXilXk2rtI8ekC', 2, '取出一个鸡蛋，打入小碗中。

💡 提示：尽量将鸡蛋完整地打入碗中，避免蛋黄破裂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (104, 'HadyXz9faXilXk2rtI8ekC', 3, '用牙签在蛋黄表面戳5个小孔，或者用筷子轻轻戳一个较大的孔。

💡 提示：戳孔可以防止蛋黄在微波炉中爆裂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (105, 'HadyXz9faXilXk2rtI8ekC', 4, '如果使用可控火候微波炉，将小碗放入微波炉中，设置为中火，加热3分钟。

💡 提示：中途可以检查一次，确保蛋黄没有完全凝固', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (106, 'HadyXz9faXilXk2rtI8ekC', 5, '如果使用不可控火候微波炉，将小碗放入微波炉中，加热1分钟，然后每30秒检查一次，直到蛋白凝固而蛋黄仍然流动。

💡 提示：每次检查时可以用筷子轻轻触碰蛋白，确认其是否凝固', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (107, 'XAoLQh3aDrYiuDeJUyezqB', 1, '准备两锅水：A锅维持100°C沸水，B锅维持30°C温水。

💡 提示：确保水温准确，可以使用温度计进行测量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (108, 'XAoLQh3aDrYiuDeJUyezqB', 2, '用漏勺将鸡蛋放入A锅，启动定时器。

💡 提示：轻轻放入，避免破裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (109, 'XAoLQh3aDrYiuDeJUyezqB', 3, '每2分钟将鸡蛋从当前锅中取出并转移到另一锅水中。

💡 提示：使用漏勺小心转移，避免烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (110, 'XAoLQh3aDrYiuDeJUyezqB', 4, '重复转移操作共16次（总时长32分钟）。

💡 提示：每次转移后检查水温，确保A锅为100°C，B锅为30°C。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (111, 'XAoLQh3aDrYiuDeJUyezqB', 5, '最后一次转移后，在B锅静置30秒。

💡 提示：这一步有助于蛋白质均匀凝固。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (112, 'XAoLQh3aDrYiuDeJUyezqB', 6, '立即将鸡蛋放入冰水中终止加热，维持30秒。

💡 提示：冰水应足够多，以完全覆盖鸡蛋。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (113, 'XAoLQh3aDrYiuDeJUyezqB', 7, '剥壳时从钝端气室处开始，沿纵轴剥离蛋膜。

💡 提示：轻轻敲击钝端，找到气室位置，更容易剥壳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (114, '6FPkVbSUaFM5tYGbjppNyE', 1, '将2个鸡蛋打入一个小碗中。

💡 提示：确保碗足够大，避免蛋液溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (115, '6FPkVbSUaFM5tYGbjppNyE', 2, '用筷子在每个蛋黄上轻轻扎2个小洞，防止加热时爆裂。

💡 提示：扎洞时要轻柔，不要把蛋黄弄破。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (116, '6FPkVbSUaFM5tYGbjppNyE', 3, '向碗中倒入35ml常温饮用水。

💡 提示：水可以保持蛋液湿润，防止过度凝固。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (117, '6FPkVbSUaFM5tYGbjppNyE', 4, '加入0.8g盐和3ml芝麻油，搅拌均匀。

💡 提示：盐和芝麻油可以使荷包蛋更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (118, '6FPkVbSUaFM5tYGbjppNyE', 5, '将碗放入微波炉中，高火（约700W）加热80秒。

💡 提示：根据微波炉功率调整时间，初次尝试可先从80秒开始。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (119, '6FPkVbSUaFM5tYGbjppNyE', 6, '到达设定时间后，使用抹布垫着手取出成品。

💡 提示：小心烫手，可以用隔热手套或厚毛巾。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (120, 'A75ZColUmVyflGhCcVUwBg', 1, '将鸡蛋打散，加入温水或高汤、食盐、生抽，轻轻搅匀，避免起泡。

💡 提示：水温应控制在40–50℃，不宜过热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (121, 'A75ZColUmVyflGhCcVUwBg', 2, '将蛋液过筛倒入耐热碗中，用牙签轻戳表面气泡。

💡 提示：过筛可显著提升蒸蛋细腻度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (122, 'A75ZColUmVyflGhCcVUwBg', 3, '覆盖保鲜膜并扎8–10个小孔，或使用微波炉专用盖（留缝隙）。

💡 提示：防止表面爆开或出现蜂窝。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (123, 'A75ZColUmVyflGhCcVUwBg', 4, '放入微波炉加热：700W下先加热1分30秒；600W下加热1分40秒–2分10秒；800W下加热1分10秒–1分40秒。视凝固情况决定是否追加20–30秒。

💡 提示：不同功率和容器影响时间，建议首次少量多次尝试。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('A75ZColUmVyflGhCcVUwBg', 5, '加热完成后取出，静置1分钟，利用余温使中心完全熟化。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (125, 'A75ZColUmVyflGhCcVUwBg', 6, '淋上香油，撒葱花即可食用。

💡 提示：若表面鼓泡或出水，说明加热过头，下次应缩短时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (126, 'SLRYLwDRHBMNTv8270bnJf', 1, '准备一个能放进微波炉的耐热容器（建议使用容量为250ml的杯子），确保容器干净且干燥。

💡 提示：选择合适的容器非常重要，避免使用金属容器。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (127, 'SLRYLwDRHBMNTv8270bnJf', 2, '将30g黄油放入容器中，用微波炉高火加热15秒至融化。

💡 提示：如果黄油没有完全融化，可以再加热5-10秒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (128, 'SLRYLwDRHBMNTv8270bnJf', 3, '打入一个鸡蛋，用筷子或叉子将其打散并搅拌均匀。

💡 提示：充分搅拌可以使蛋糕更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (129, 'SLRYLwDRHBMNTv8270bnJf', 4, '加入10g白（红）糖和1g盐，继续搅拌均匀。

💡 提示：糖的量可以根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (130, 'SLRYLwDRHBMNTv8270bnJf', 5, '筛入15g面粉和2.5g泡打粉，搅拌至无干粉状态。

💡 提示：筛入面粉可以避免结块，使蛋糕更加松软。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (131, 'SLRYLwDRHBMNTv8270bnJf', 6, '加入你喜欢的口味食材（如巧克力、香蕉、坚果、饼干屑等），轻轻搅拌均匀。

💡 提示：如果加入液体食材（如牛奶），请少量多次加入，以防止水分过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (132, 'SLRYLwDRHBMNTv8270bnJf', 7, '将混合好的面糊倒入容器中，不要超过容器的3/4。

💡 提示：留出足够的空间让蛋糕膨胀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (133, 'SLRYLwDRHBMNTv8270bnJf', 8, '将容器放入微波炉中，高火加热1分钟。

💡 提示：具体时间可能因微波炉功率不同而有所差异，注意观察蛋糕状态。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (134, 'SLRYLwDRHBMNTv8270bnJf', 9, '取出容器（小心烫手），可以用牙签插入蛋糕中心检查是否熟透。

💡 提示：如果牙签上没有粘附面糊，说明蛋糕已经熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (135, 'SLRYLwDRHBMNTv8270bnJf', 10, '稍微冷却后，即可享用美味的微波炉蛋糕。

💡 提示：趁热吃口感最佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (136, 'SEBSUOuPRAM80pXiq56w9Y', 1, '将200克面粉放入大碗中，慢慢倒入100毫升开水，边倒边用筷子搅拌成絮状。再加入50毫升冷水，揉成光滑面团。

💡 提示：热水和冷水的比例可以使面团更加柔软有弹性', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (137, 'SEBSUOuPRAM80pXiq56w9Y', 2, '将揉好的面团覆盖湿布或保鲜膜，静置醒发20分钟。

💡 提示：醒发时间不宜少于20分钟，否则不易擀薄', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (138, 'SEBSUOuPRAM80pXiq56w9Y', 3, '将醒发好的面团分成每份约100克的小剂子，搓圆后擀成薄片。

💡 提示：尽量擀得薄一些，这样层次更丰富', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (139, 'SEBSUOuPRAM80pXiq56w9Y', 4, '在擀好的面皮上均匀涂抹15毫升食用油，撒上3克盐，然后从一端卷起成蜗牛状，松弛10分钟。

💡 提示：涂抹油和撒盐要均匀，这样煎出来的饼更有层次感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (140, 'SEBSUOuPRAM80pXiq56w9Y', 5, '将松弛好的面团再次擀成薄饼，厚度均匀。

💡 提示：擀的时候要轻柔，避免破皮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (141, 'SEBSUOuPRAM80pXiq56w9Y', 6, '平底锅预热，倒入适量油，小火加热至油温约150℃，放入擀好的饼皮，煎至两面金黄起泡，每面约3-4分钟。

💡 提示：煎制时火候要小，以免外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (142, 'SEBSUOuPRAM80pXiq56w9Y', 7, '在煎好的饼上依次铺入煎蛋、生菜、火腿、芝士片等配料，卷起即可。

💡 提示：可以根据个人口味增减配料，建议总重控制在100克以内', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (143, 'w8GyOcz3eIFjyqY1nxUL0F', 1, '将桂圆肉扒出，用清水洗两次，放入碗中浸泡10分钟

💡 提示：桂圆肉浸泡后会更加软糯', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (144, 'w8GyOcz3eIFjyqY1nxUL0F', 2, '红枣用清水洗两次，放入碗中浸泡10分钟

💡 提示：红枣浸泡后更容易煮烂，释放更多甜味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (145, 'w8GyOcz3eIFjyqY1nxUL0F', 3, '糯米放入电饭锅中，清水淘米两次后，加入2000ml水

💡 提示：淘米可以去除杂质，使粥更加清爽', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (146, 'w8GyOcz3eIFjyqY1nxUL0F', 4, '将泡好的桂圆和红枣加入电饭锅

💡 提示：确保桂圆和红枣均匀分布在锅中', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (147, 'w8GyOcz3eIFjyqY1nxUL0F', 5, '打开电饭锅煮饭模式，煮约50分钟后粥成

💡 提示：根据电饭锅的具体型号调整时间，以粥的稠度为准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (148, '2O2mevjfRg3FLuUi0qP5F2', 1, '将新鲜玉米剥去外皮，保留最内层的2-3层玉米皮，以增加风味。

💡 提示：保留部分玉米皮可以增加玉米的香气', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (149, '2O2mevjfRg3FLuUi0qP5F2', 2, '将处理好的玉米放入锅中，加入约300ml的水，水量以刚好淹过玉米为宜。

💡 提示：水量不宜过多，以免稀释味道', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (150, '2O2mevjfRg3FLuUi0qP5F2', 3, '在水中加入约5克盐和5克糖（如果喜欢甜味的话），搅拌均匀。

💡 提示：加糖可以使玉米更加鲜甜，但也可以不加', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (151, '2O2mevjfRg3FLuUi0qP5F2', 4, '开大火将水煮沸后，转小火加盖继续煮15-20分钟。最长不宜超过30分钟，以免玉米过于软烂。

💡 提示：用小火慢煮可以让玉米更加入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (152, '2O2mevjfRg3FLuUi0qP5F2', 5, '煮熟后，关火，将玉米捞出沥干水分，待稍微冷却后即可食用。

💡 提示：稍微冷却后的玉米口感更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (153, 'afyQukhZhBxjiu1yCgoIHk', 1, '将鸡蛋放入电饭煲中。鸡蛋不可互相堆叠，应皆在底部，并留有空间可以晃动。

💡 提示：确保鸡蛋之间有足够的空间，避免碰撞破裂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (154, 'afyQukhZhBxjiu1yCgoIHk', 2, '倒入淹过鸡蛋约2公分的冷水。

💡 提示：水要完全淹没鸡蛋，保证均匀加热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (155, 'afyQukhZhBxjiu1yCgoIHk', 3, '开盖，使用最大功率加热至水滚起（大约85-95度，稍微滚动，不需完全沸腾）。

💡 提示：观察水面，当水开始冒小泡并轻微滚动时即可关火', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (156, 'afyQukhZhBxjiu1yCgoIHk', 4, '关火，盖上盖子，让鸡蛋静置。想要中央有流动的蛋黄，需静置6分钟；若想要完全煮熟的易碎蛋黄，需静置10分钟。

💡 提示：根据个人喜好调整静置时间，以达到理想的蛋黄状态', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (157, 'afyQukhZhBxjiu1yCgoIHk', 5, '沥干水分，用冷水冲洗鸡蛋约1分钟，然后去壳食用。

💡 提示：冷水冲洗有助于停止烹饪过程，使蛋壳更容易剥离', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (158, 'kzLPHil1N60srD4j35yMEL', 1, '取出平底锅（不沾平底锅最佳），加入10ml - 15ml食用油。

💡 提示：确保锅底均匀涂抹一层薄油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (159, 'kzLPHil1N60srD4j35yMEL', 2, '开火，放入饺子（尽量平均铺开，不宜堆叠）。

💡 提示：饺子之间留有空隙，避免粘连', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (160, 'kzLPHil1N60srD4j35yMEL', 3, '立刻加入150ml清水，水线没过饺子平均高度的1/2。

💡 提示：水量要适中，过多会导致饺子皮软烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (161, 'kzLPHil1N60srD4j35yMEL', 4, '盖上锅盖，大火加热。

💡 提示：保持大火，使水分迅速蒸发', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (162, 'kzLPHil1N60srD4j35yMEL', 5, '当锅中水分仅剩2mm时，转中火开始煎制。

💡 提示：此时饺子底部开始形成脆皮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (163, 'kzLPHil1N60srD4j35yMEL', 6, '当水分全部蒸发后，摇晃平底锅使饺子受热均匀。

💡 提示：轻轻摇动锅子，防止饺子粘底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (164, 'kzLPHil1N60srD4j35yMEL', 7, '撒入适量黑芝麻和葱花，再焖10秒。

💡 提示：增加香气和美观', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (165, 'kzLPHil1N60srD4j35yMEL', 8, '1-2分钟后夹出一个饺子观察底部，若出现金黄色脆皮立即取出。

💡 提示：注意不要煎糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (166, 'kmX1mciO957s41SmIyzTKj', 1, '将50g纯干燕麦片与100ml牛奶混合在一个大碗中，搅拌均匀至黏稠状。

💡 提示：确保燕麦充分吸收牛奶，达到合适的粘稠度', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (167, 'kmX1mciO957s41SmIyzTKj', 2, '在另一个碗中，将2个鸡蛋（或2个蛋清和1个蛋黄）打散，搅拌均匀至颜色单一。

💡 提示：可以加入少许盐和胡椒粉调味，如果喜欢咸口的话', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (168, 'kmX1mciO957s41SmIyzTKj', 3, '将打好的鸡蛋液倒入燕麦牛奶混合物中，继续搅拌至均匀且黏稠。

💡 提示：确保所有成分充分混合，没有结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (169, 'kmX1mciO957s41SmIyzTKj', 4, '在平底锅中加入一层薄薄的黄油，小火加热至黄油融化并覆盖整个锅底。

💡 提示：使用小火，避免黄油烧焦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (170, 'kmX1mciO957s41SmIyzTKj', 5, '将搅拌好的食材倒入平底锅中，摊开成圆形饼状，厚度约为0.5cm。

💡 提示：尽量摊得均匀，这样煎出来的饼才会更美观', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (171, 'kmX1mciO957s41SmIyzTKj', 6, '小火加热3分钟，待底部凝固后，撒上蔬菜碎叶（如果使用），然后翻面继续加热2分钟。

💡 提示：翻面前确保底部已经凝固，否则容易破碎', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (172, 'kmX1mciO957s41SmIyzTKj', 7, '煎至两面金黄，出锅装盘。

💡 提示：可以用铲子轻轻按压饼面，检查是否熟透', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (173, '4ENsmGSIrrm02ciYFEyDH2', 1, '将牛奶倒入早餐杯中（冷的即可）

💡 提示：选择你喜欢的杯子，确保容量足够', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (174, '4ENsmGSIrrm02ciYFEyDH2', 2, '准备200ml水，如果是直饮水直接加入燕麦，否则请烧开后加入燕麦

💡 提示：使用直饮水可以节省时间', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (175, '4ENsmGSIrrm02ciYFEyDH2', 3, '将水和燕麦放入锅中，大火煮沸后转小火煮2分钟

💡 提示：注意不要让燕麦粘底，适时搅拌', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (176, '4ENsmGSIrrm02ciYFEyDH2', 4, '将煮好的燕麦捞出倒入牛奶中（尽量不要将煮燕麦的水也倒入牛奶，影响口感）

💡 提示：用漏网捞出燕麦，避免水分过多', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (177, '4ENsmGSIrrm02ciYFEyDH2', 5, '热锅，锅内放一层底油，油热后煎鸡蛋，每面煎20秒，可选调底味（3g椒盐）

💡 提示：中小火煎蛋，防止外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (178, '4ENsmGSIrrm02ciYFEyDH2', 6, '关火，将煎好的鸡蛋装盘

💡 提示：煎蛋时可以用铲子轻轻按压，使蛋黄均匀受热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (179, '0PXxUBY0ZsWJMpFWcyWh14', 1, '将空气炸锅预热至200°C，大约需要3-5分钟。

💡 提示：预热可以确保面包片均匀受热，表面更加酥脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (180, '0PXxUBY0ZsWJMpFWcyWh14', 2, '取出两片全麦面包片，可以选择在面包片上轻轻喷一层薄油（可选），以增加口感。

💡 提示：喷油可以使面包片表面更加金黄酥脆，但不喷油也可以，根据个人喜好选择。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (181, '0PXxUBY0ZsWJMpFWcyWh14', 3, '将面包片平铺放入空气炸锅的篮子中，不要重叠。

💡 提示：平铺放置可以确保面包片受热均匀，避免局部烤焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (182, '0PXxUBY0ZsWJMpFWcyWh14', 4, '将空气炸锅设置为200°C，烘烤5分钟。

💡 提示：中途可以翻面一次，使两面都变得酥脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (183, '0PXxUBY0ZsWJMpFWcyWh14', 5, '烘烤完成后，用夹子小心取出面包片，放在架子上稍微冷却一下即可食用。

💡 提示：刚出炉的面包片非常烫手，请小心操作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (184, 'I8PfpZh5kzNsbBtZlYCEQq', 1, '将3个鸡蛋打入大碗中，加入1克盐，用打蛋器搅打至起泡，然后加入10克全脂牛奶或奶油，继续搅拌均匀。

💡 提示：充分搅拌可以使蛋液更加细腻，加入牛奶后再次搅拌均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (185, 'I8PfpZh5kzNsbBtZlYCEQq', 2, '取一个不粘平底锅，放入5克黄油，开小火加热至黄油完全融化。

💡 提示：使用小火可以防止黄油烧焦，保持黄油的香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (186, 'I8PfpZh5kzNsbBtZlYCEQq', 3, '将蛋液倒入锅中，用铲子不断轻轻搅拌，使蛋液均匀受热，形成细密的蛋花。

💡 提示：持续搅拌可以使蛋花更加细密，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (187, 'I8PfpZh5kzNsbBtZlYCEQq', 4, '当蛋液大部分凝固但仍略带湿润时，关火，利用余温继续翻动几下，使蛋花更加松软。

💡 提示：不要过度烹饪，保留一定的湿润感会使炒蛋更加嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (188, 'I8PfpZh5kzNsbBtZlYCEQq', 5, '将炒好的蛋盛出，装盘即可。

💡 提示：趁热食用口感最佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (189, 'v3fD6ozOwSKvNLhIFhC5P4', 1, '将鸡蛋放入锅中，加入足够的冷水，大火煮沸后继续煮8分钟。

💡 提示：确保水完全覆盖鸡蛋。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (190, 'v3fD6ozOwSKvNLhIFhC5P4', 2, '用漏网捞出鸡蛋，立即放入冷水中浸泡，直至完全冷却。

💡 提示：过冷水可以让鸡蛋壳更容易剥落。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (191, 'v3fD6ozOwSKvNLhIFhC5P4', 3, '用勺子轻轻敲打鸡蛋表面，使其产生细小裂缝。

💡 提示：裂缝不宜过大，以免煮制过程中蛋黄流出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (192, 'v3fD6ozOwSKvNLhIFhC5P4', 4, '将鸡蛋重新放回锅中，加入八角、香叶、桂皮、茴香、冰糖、红茶、生抽、老抽和食盐。

💡 提示：确保所有调料均匀分布在锅中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (193, 'v3fD6ozOwSKvNLhIFhC5P4', 5, '加水至没过鸡蛋，大火煮沸后转中小火煮15分钟。

💡 提示：保持中小火以避免水分蒸发过快。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (194, 'v3fD6ozOwSKvNLhIFhC5P4', 6, '关火后捞出料渣，让鸡蛋在汤汁中继续浸泡至少1小时，以便更好地入味。

💡 提示：浸泡时间越长，味道越浓郁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (195, '4TMOcPhdbEZKLHDXH62mRx', 1, '将2个新鲜鸡蛋打入碗中，用筷子或打蛋器打散，直至蛋液均匀。

💡 提示：打蛋时尽量不要打出太多气泡，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (196, '4TMOcPhdbEZKLHDXH62mRx', 2, '取另一个容器，倒入260ml温水（约20-30℃），加入2g盐，搅拌至盐完全溶解。

💡 提示：使用温水可以使蛋液更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (197, '4TMOcPhdbEZKLHDXH62mRx', 3, '将盐水缓缓倒入打散的蛋液中，顺时针或逆时针单方向搅拌均匀，去除表面的气泡。

💡 提示：搅拌时要轻柔，避免产生过多气泡。可以使用筛子过滤蛋液，使口感更细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (198, '4TMOcPhdbEZKLHDXH62mRx', 4, '将蛋液倒入一个适合蒸制的碗中，用锡纸或保鲜膜覆盖碗口，四周留出一些空隙以便蒸汽流通。

💡 提示：如果使用保鲜膜，可以在膜上扎几个小孔，以防止保鲜膜鼓起。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (199, '4TMOcPhdbEZKLHDXH62mRx', 5, '锅中加水，大火烧开后，将装有蛋液的碗放入锅中，盖上锅盖，转中小火蒸8-12分钟。

💡 提示：蒸制时间根据蛋液的厚度和锅具的不同可能有所变化，可以用牙签插入蛋液中心检查是否凝固。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (200, '4TMOcPhdbEZKLHDXH62mRx', 6, '蒸好后关火，让蛋液在锅中焖2-3分钟，然后取出稍微晾凉即可食用。

💡 提示：焖制可以让蛋液更加均匀地凝固，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (201, 'b1VBuMQWEStk52z9Hi9aFf', 1, '将酵母和白糖加入温水中，搅拌均匀，静置5-10分钟，直到表面出现泡沫。

💡 提示：确保水温不要过高，否则会杀死酵母。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (202, 'b1VBuMQWEStk52z9Hi9aFf', 2, '将面粉倒入大碗中，慢慢加入酵母水，边加边用筷子搅拌成絮状。

💡 提示：根据面粉吸水性不同，水量可适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (203, 'b1VBuMQWEStk52z9Hi9aFf', 3, '将面团揉至光滑，盖上湿布或保鲜膜，放在温暖处进行第一次发酵，大约1小时，直到面团体积膨胀至原来的两倍。

💡 提示：发酵环境温度应在28-30°C之间，可以放在烤箱内并开启发酵功能。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (204, 'b1VBuMQWEStk52z9Hi9aFf', 4, '发酵好的面团取出，揉搓排气，然后擀成长方形薄片，刷上一层薄薄的食用油。

💡 提示：擀面时尽量保持厚度均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (205, 'b1VBuMQWEStk52z9Hi9aFf', 5, '将长方形薄片从一端开始卷起，卷成一个长条，然后切成5个等份的小剂子。

💡 提示：切的时候刀要快，避免压扁面团。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (206, 'b1VBuMQWEStk52z9Hi9aFf', 6, '取一个小剂子，用筷子在中间压一下，然后双手捏住两端轻轻拉长，再反向扭转几圈，最后将两端向下对折，形成花卷形状。

💡 提示：动作要轻柔，以免破坏花卷的层次感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (207, 'b1VBuMQWEStk52z9Hi9aFf', 7, '将整形好的花卷放入蒸笼中，盖上锅盖，进行第二次发酵，大约15-20分钟。

💡 提示：二次发酵可以使花卷更加松软。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (208, 'b1VBuMQWEStk52z9Hi9aFf', 8, '锅中加水400毫升，大火烧开后，将装有花卷的蒸笼放入锅中，转中火蒸15分钟。

💡 提示：蒸制过程中不要频繁开盖，以免影响花卷的蓬松度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (209, 'b1VBuMQWEStk52z9Hi9aFf', 9, '关火后，稍等2-3分钟再打开锅盖，取出花卷放凉至不烫手即可食用。

💡 提示：刚出锅的花卷非常烫，建议稍微冷却后再食用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (210, 'WBI8IHLPu4m5nF0QKnejIl', 1, '将糍粑切成约2cm x 4cm的小长方形块，便于后面煎制。

💡 提示：切块时尽量保持大小一致，以确保均匀受热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (211, 'WBI8IHLPu4m5nF0QKnejIl', 2, '在碗里打入一个鸡蛋并搅打均匀，加入2g食用盐（可选）。

💡 提示：加盐可以提升蛋液的味道，但也可以不加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (212, 'WBI8IHLPu4m5nF0QKnejIl', 3, '将切好的糍粑块逐一放入搅打好的鸡蛋液中，确保每块糍粑双面都均匀涂抹上蛋液。

💡 提示：用筷子或叉子帮助翻动糍粑，确保每个面都裹上蛋液。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (213, 'WBI8IHLPu4m5nF0QKnejIl', 4, '在平底锅中倒入10-15ml植物油，开小火预热后，将裹好蛋液的糍粑块间隔放入锅中，小火慢煎。

💡 提示：注意糍粑块之间要留有空隙，防止粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (214, 'WBI8IHLPu4m5nF0QKnejIl', 5, '待一面煎至金黄色后，将剩下的鸡蛋液慢慢倒在糍粑表面，然后用筷子或铲子为糍粑翻面，继续煎另一面直至金黄色。

💡 提示：翻面前确保糍粑已经定型，避免碎裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (215, 'TkZk5Yp7gvMgkzua39wAQa', 1, '将65g水浸金枪鱼、50mL蛋黄酱和10–15mL俄式酸黄瓜汁倒入碗中，用勺子搅拌均匀，确保金枪鱼块被搅碎，酱料整体呈糊状，并备用。

💡 提示：搅拌时尽量将金枪鱼块搅碎，使酱料更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (216, 'TkZk5Yp7gvMgkzua39wAQa', 2, '将一片吐司放在轻食机上（如果没有轻食机，可以用平底锅或烤箱代替）。

💡 提示：如果使用平底锅，可以在锅中刷一层薄油，用中小火加热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (217, 'TkZk5Yp7gvMgkzua39wAQa', 3, '将做好的金枪鱼酱涂抹到吐司上，用量约为10-15mL。

💡 提示：可以根据个人喜好调整金枪鱼酱的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (218, 'TkZk5Yp7gvMgkzua39wAQa', 4, '如果喜欢，可以在金枪鱼酱上放一片芝士片和一片火腿片。

💡 提示：芝士片和火腿片是可选项，根据个人口味添加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (219, 'TkZk5Yp7gvMgkzua39wAQa', 5, '将另一片吐司覆盖在上面，然后按压轻食机，开机加热3-4分钟。

💡 提示：注意在按压操作之前不要将轻食机电源接通，以免引发安全问题。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (220, 'TkZk5Yp7gvMgkzua39wAQa', 6, '待轻食机自动停止加热后，取出三明治，装盘即可食用。

💡 提示：如果使用平底锅，煎至两面金黄即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (221, '3gd7xyZ5hvI7P3MEjgF8ET', 1, '将鸡蛋放入锅中，加入足够的冷水，大火煮沸后转中小火煮7分钟。

💡 提示：煮鸡蛋时用冷水下锅，可以防止蛋壳破裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (222, '3gd7xyZ5hvI7P3MEjgF8ET', 2, '将煮熟的鸡蛋捞出，立即放入冷水中冷却，然后剥壳并捣碎。

💡 提示：用冷水浸泡可以帮助鸡蛋快速冷却，便于剥壳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (223, '3gd7xyZ5hvI7P3MEjgF8ET', 3, '在一个小碗中，将捣碎的鸡蛋与蛋黄酱、盐和黑胡椒混合均匀。

💡 提示：调味料可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (224, '3gd7xyZ5hvI7P3MEjgF8ET', 4, '在平底锅中加入黄油，用中火加热至融化，然后放入培根煎至两面金黄且酥脆，约需3-4分钟。

💡 提示：煎培根时注意翻面，使其受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (225, '3gd7xyZ5hvI7P3MEjgF8ET', 5, '将煎好的培根放在厨房纸巾上沥干多余的油脂。

💡 提示：沥干油脂可以让三明治更加清爽不油腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (226, '3gd7xyZ5hvI7P3MEjgF8ET', 6, '将吐司切去四边，备用。

💡 提示：切去四边可以使三明治更加美观。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (227, '3gd7xyZ5hvI7P3MEjgF8ET', 7, '在一片吐司上涂抹一层薄薄的黄油，然后放上一层鸡蛋酱，再铺上煎好的培根。

💡 提示：涂抹黄油可以使吐司更加香脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (228, '3gd7xyZ5hvI7P3MEjgF8ET', 8, '盖上另一片吐司，轻轻按压，然后切成两个三角形装盘。

💡 提示：切开前轻轻按压可以使三明治更加紧实。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (229, 'dR4o2q209C79ahYt3XhQYm', 1, '将77g面粉和5g盐放入一个小碗中，搅拌均匀。

💡 提示：确保面粉和盐充分混合，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (230, 'dR4o2q209C79ahYt3XhQYm', 2, '将100ml食用油倒入锅中，加热至约200°C（油温达到后，筷子插入油中会迅速冒泡）。

💡 提示：注意油温不要过高，以免烧焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (231, 'dR4o2q209C79ahYt3XhQYm', 3, '将热油缓缓倒入面粉中，边倒边用筷子快速搅拌，直至面粉完全吸收油脂，形成细腻、无颗粒的糊状。

💡 提示：一定要快速搅拌，防止面粉结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (232, 'dR4o2q209C79ahYt3XhQYm', 4, '待油酥稍微冷却后，即可使用。如果暂时不用，可以盖上保鲜膜，放置一旁备用。

💡 提示：油酥最好现做现用，以保证最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (233, 'R8njUQAhKg8aHYwQy7Ycxb', 1, '将干辣椒面、孜然粉、胡椒粉、五香粉、食盐、花椒粉、鸡精、十三香、麻辣鲜和白芝麻放入一个大碗中，搅拌均匀。

💡 提示：确保所有粉末混合均匀，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (234, 'R8njUQAhKg8aHYwQy7Ycxb', 2, '在锅中倒入约200毫升食用油，用中小火加热至油温达到180-200摄氏度（油开始微微冒烟）。

💡 提示：注意不要让油温过高，以免烧焦调料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (235, 'R8njUQAhKg8aHYwQy7Ycxb', 3, '将热油分三次倒入混合好的调料中，每次倒入1/3的油量，并迅速搅拌均匀。

💡 提示：分次倒入热油可以更好地激发调料的香气，同时防止调料结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (236, 'R8njUQAhKg8aHYwQy7Ycxb', 4, '待油温稍微降低后，加入香油、生抽、花椒油和蚝油，再次搅拌均匀。

💡 提示：最后加入液体调料可以使酱料更加鲜美，但要注意不要加太多，以免稀释酱料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (237, 'M3H8zF2XUZ2FlVi3h0sTvA', 1, '将锅置于炉灶上，开中火预热。

💡 提示：确保锅子干净无水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (238, 'M3H8zF2XUZ2FlVi3h0sTvA', 2, '向锅中倒入100ml油。

💡 提示：油温不宜过高，以免糖色发苦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (239, 'M3H8zF2XUZ2FlVi3h0sTvA', 3, '加入200g敲碎的冰糖。

💡 提示：尽量选择大小均匀的小块冰糖，便于融化', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (240, 'M3H8zF2XUZ2FlVi3h0sTvA', 4, '调整火力为中火，开始搅拌。

💡 提示：保持连续搅拌，防止糖粘锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (241, 'M3H8zF2XUZ2FlVi3h0sTvA', 5, '当糖液变成棕褐色时，转为小火继续搅拌。

💡 提示：注意观察颜色变化，避免过度焦化', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (242, 'M3H8zF2XUZ2FlVi3h0sTvA', 6, '糖液变稀，颜色变为红茶色后，继续搅拌至酱红色并出现小泡泡。

💡 提示：此时糖色已接近完成，需密切注意', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (243, 'M3H8zF2XUZ2FlVi3h0sTvA', 7, '当小泡泡逐渐消失，出现大泡泡时，糖色完成。

💡 提示：快速进行下一步操作，避免糖色发苦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (244, 'M3H8zF2XUZ2FlVi3h0sTvA', 8, '根据需要选择操作1或操作2：
操作1：直接加入400ml开水降温。
操作2：加入葱姜蒜花椒等调味品进行翻炒。

💡 提示：无论哪种操作都一定要提前准备好并快速执行', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (245, 'K6zvXIRbmejiJpilme4YJx', 1, '在一个小碗中，将清水、生抽、白糖、白醋和料酒按照比例混合均匀。

💡 提示：确保所有调料充分溶解，特别是白糖完全融化。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (246, 'K6zvXIRbmejiJpilme4YJx', 2, '将调好的糖醋汁倒入锅中，开中小火慢慢加热。

💡 提示：中小火可以避免糖醋汁烧焦，同时让味道更加融合。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (247, 'K6zvXIRbmejiJpilme4YJx', 3, '持续搅拌，直到糖醋汁变得稍微浓稠，颜色略微变深。

💡 提示：观察糖醋汁的状态，当它开始冒泡且粘稠度增加时，说明已经接近完成。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (248, 'K6zvXIRbmejiJpilme4YJx', 4, '最后转大火收汁，快速翻炒几下，使糖醋汁更加浓郁。

💡 提示：大火收汁可以让糖醋汁表面形成一层光泽，提升菜肴的卖相。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (249, 'yW1odkdFoQmDue3Kmmea3y', 1, '将开洋泡入50度温水中，加入10ml料酒去腥，泡10分钟后取出沥干水分。

💡 提示：泡发开洋时，水温不宜过高，以免破坏其鲜味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (250, 'yW1odkdFoQmDue3Kmmea3y', 2, '将葱洗净，切成5cm长的段，擦干表面水分；香菜洗净，切成5cm长的段，擦干表面水分。

💡 提示：确保葱和香菜表面干燥，避免炸油时溅油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (251, 'yW1odkdFoQmDue3Kmmea3y', 3, '将洋葱切成丝，放入锅中用热水煮5分钟，去除辛辣味，取出后沥干水分并冷却。

💡 提示：煮洋葱可以去除辛辣味，使其更加柔和。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (252, 'yW1odkdFoQmDue3Kmmea3y', 4, '将姜去皮，切成片，擦干表面水分。

💡 提示：姜片擦干水分，防止炸油时溅油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (253, 'yW1odkdFoQmDue3Kmmea3y', 5, '在锅中倒入全部油，冷油下料，放入预处理好的葱段、姜片、洋葱丝、开洋（如果使用）和香菜（如果使用），开中小火慢慢炸20-25分钟，直至材料呈金黄色且香味四溢。

💡 提示：冷油下料可以使食材中的香味充分释放，同时避免高温下料导致焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (254, 'yW1odkdFoQmDue3Kmmea3y', 6, '关火，待油温稍降后，用滤网过滤掉所有料渣，保留清澈的葱油。

💡 提示：过滤后的葱油更清澈，便于储存和使用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (255, 'pj4DzHAKYIZJ1MGTiiDGOo', 1, '将蒜头拍碎，去皮后切成细末。

💡 提示：蒜头拍碎后再切末更容易释放香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (256, 'pj4DzHAKYIZJ1MGTiiDGOo', 2, '在蘸料碟中加入酱油。

💡 提示：根据个人口味调整酱油量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (257, 'pj4DzHAKYIZJ1MGTiiDGOo', 3, '起锅，加入花生油，用中小火加热至油温达到180°C（约半分钟后）。

💡 提示：可以用筷子测试油温，周围有小气泡冒出即可', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (258, 'pj4DzHAKYIZJ1MGTiiDGOo', 4, '将拍好的蒜末倒入热油中，炸约30秒至金黄色。

💡 提示：注意不要炸焦，以免影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (259, 'pj4DzHAKYIZJ1MGTiiDGOo', 5, '关火，迅速将热油连同蒜末一起倒入装有酱油的蘸料碟中。

💡 提示：快速倒入可以更好地保留蒜香', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (260, 'pj4DzHAKYIZJ1MGTiiDGOo', 6, '撒上炒香的白芝麻，用筷子搅拌均匀即可。

💡 提示：白芝麻提前炒香会更加香脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (261, 'baVPKaRRkUGB2RJIqWcYpr', 1, '将利口酒杯放入冰箱冷藏约5分钟，使其冷却。

💡 提示：冷藏杯子有助于保持酒精的层次分明', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (262, 'baVPKaRRkUGB2RJIqWcYpr', 2, '从冰箱中取出利口酒杯，在最底层倒入10ml甘露咖啡酒。

💡 提示：确保倒入时动作轻柔，避免溅出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (263, 'baVPKaRRkUGB2RJIqWcYpr', 3, '顺着吧勺缓缓倒入10ml爱尔兰百利甜酒，速度要慢，大约需要15秒。

💡 提示：使用吧勺可以防止两种酒混合，保持层次分明', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (264, 'baVPKaRRkUGB2RJIqWcYpr', 4, '最后在上层缓缓倒入10ml蓝天原味伏特加，同样需要15秒。

💡 提示：确保伏特加完全覆盖在最上层', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (265, 'baVPKaRRkUGB2RJIqWcYpr', 5, '用打火机轻轻加热杯口边缘，然后点燃最上层的伏特加。

💡 提示：加热杯口可以防止点燃时火焰过大，注意安全', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (266, 'baVPKaRRkUGB2RJIqWcYpr', 6, '提供一个吸管，插入燃烧的鸡尾酒中，快速吸入。

💡 提示：吸管中的氧气不足，火苗会自动熄灭，但要注意不要碰到杯口以免烫伤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (267, '1mStxkBPI2ET98CxZ3H2qx', 1, '将青柠切成两半，取其中一半再切成小块，放入海波杯中。

💡 提示：切青柠时尽量保留一些果肉，以增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (268, '1mStxkBPI2ET98CxZ3H2qx', 2, '用研杵轻轻捣压青柠块，使其出汁。

💡 提示：不要过度捣压，以免产生苦味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (269, '1mStxkBPI2ET98CxZ3H2qx', 3, '取3-4片薄荷叶，沿着杯口涂抹一圈，然后将其放入杯中。

💡 提示：涂抹薄荷叶可以增加杯子的香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (270, '1mStxkBPI2ET98CxZ3H2qx', 4, '加入20ml糖浆。

💡 提示：糖浆可以根据个人口味调整用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (271, '1mStxkBPI2ET98CxZ3H2qx', 5, '加入45ml白朗姆酒。

💡 提示：倒入朗姆酒时要小心，避免溅出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (272, '1mStxkBPI2ET98CxZ3H2qx', 6, '将剩下的半块青柠用手动压汁器榨汁，将汁水倒入杯中。

💡 提示：手动压汁器可以更好地提取青柠汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (273, '1mStxkBPI2ET98CxZ3H2qx', 7, '用搅拌棒轻轻搅拌几下，使糖浆与青柠汁充分混合。

💡 提示：搅拌时不要过于猛烈，以免破坏薄荷叶。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (274, '1mStxkBPI2ET98CxZ3H2qx', 8, '向杯中加入碎冰，直到占杯中的3/4。

💡 提示：确保碎冰足够多，以保持饮品的凉爽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (275, '1mStxkBPI2ET98CxZ3H2qx', 9, '加入冰镇苏打水，直至刚好淹没碎冰。

💡 提示：苏打水要慢慢倒入，以免溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (276, '1mStxkBPI2ET98CxZ3H2qx', 10, '用搅拌棒旋转搅拌约半分钟。

💡 提示：搅拌时要均匀，使所有成分充分混合。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (277, '1mStxkBPI2ET98CxZ3H2qx', 11, '最后，用剩余的碎冰补满杯子。

💡 提示：确保杯子顶部也有足够的碎冰。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (278, '1mStxkBPI2ET98CxZ3H2qx', 12, '取一片薄荷叶，轻轻拍打几下，插入碎冰中作为装饰。

💡 提示：拍打薄荷叶可以释放其香气，提升饮品的整体风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (279, 'UMmRb1RzoAZ3kXvFnWJkrx', 1, '将冬瓜去皮，去籽，切成小块（每块不超过 4cm）。

💡 提示：切块时尽量保持大小均匀，以便于后续熬制', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (280, 'UMmRb1RzoAZ3kXvFnWJkrx', 2, '将切好的冬瓜块和冰糖混合均匀，盖上保鲜膜放入冰箱冷藏 2 小时以上。

💡 提示：冷藏过程中，冬瓜会出水，与冰糖充分融合，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (281, 'UMmRb1RzoAZ3kXvFnWJkrx', 3, '将冷藏后的冬瓜块连同渗出的水分一起倒入大锅中，大火煮开后转中小火慢慢熬制 1~2 个小时。

💡 提示：熬制过程中要经常搅拌，防止糊锅。熬至冬瓜变软且汤汁浓稠呈淡黄色即可', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (282, 'UMmRb1RzoAZ3kXvFnWJkrx', 4, '使用过滤网将煮好的冬瓜茶液过滤，取出冬瓜块，只保留茶液。

💡 提示：过滤时可以用勺子轻轻按压冬瓜块，使更多的汁液流出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (283, 'UMmRb1RzoAZ3kXvFnWJkrx', 5, '将过滤后的冬瓜茶液放凉后，倒入干净的容器中，放入冰箱冷藏。

💡 提示：冷藏后的冬瓜茶口感更佳，建议提前制作好，冷藏保存', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (284, 'UMmRb1RzoAZ3kXvFnWJkrx', 6, '享用时，根据个人喜好添加适量的水或其他饮品，冷热皆宜。

💡 提示：浓缩汁与水的比例一般为1:3或1:4，可根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (285, 'fCtSjtWXaOibW64SDAtBvy', 1, '将柠檬洗净，对半切开（刀方向垂直于柠檬的头尾连线），再从其中一半中切取一片柠檬备用。

💡 提示：确保柠檬干净，避免果皮上的杂质进入饮品。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (286, 'fCtSjtWXaOibW64SDAtBvy', 2, '将剩下的柠檬再次对半切，得到4瓣柠檬。用压汁器压出柠檬汁，置于容器中备用。

💡 提示：尽量挤出所有柠檬汁，但避免挤入过多果肉。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (287, 'fCtSjtWXaOibW64SDAtBvy', 3, '选择一个容量约为1升的大型玻璃杯或铁皮酒桶。

💡 提示：杯子越大，冰块融化得越慢，饮品保持冷饮的时间也越长。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (288, 'fCtSjtWXaOibW64SDAtBvy', 4, '将冰块和挤压过的柠檬放入杯中，可以根据个人喜好设计柠檬与冰块的摆放。

💡 提示：冰块越多，饮品越凉爽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (289, 'fCtSjtWXaOibW64SDAtBvy', 5, '倒入15毫升柠檬汁（如果喜酸可以加多点或全加）。

💡 提示：根据个人口味调整柠檬汁的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (290, 'fCtSjtWXaOibW64SDAtBvy', 6, '沿杯壁缓慢倒入500毫升可口可乐至距离杯口3/4处。

💡 提示：慢慢倒入可乐，避免泡沫过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (291, 'fCtSjtWXaOibW64SDAtBvy', 7, '最后倒入100毫升波旁威士忌直至满杯。

💡 提示：威士忌的量可以根据个人喜好调整，但建议不超过100毫升。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (292, 'ljhGcW8WzxtMbtVMF7ANoA', 1, '取袋泡红茶2包放入杯中，加入180-200mL沸水。

💡 提示：尽量保持杯子内部温暖，例如使用开口较小的杯子或盖上盖子。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (293, 'ljhGcW8WzxtMbtVMF7ANoA', 2, '等待3-5分钟，让茶充分冲泡。

💡 提示：等待时间结束后可提起或搅动茶包以使冲泡更加均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (294, 'ljhGcW8WzxtMbtVMF7ANoA', 3, '取出茶包，称取11-12g奶粉和5-7g砂糖，分别加入前一步骤得到的液体中。

💡 提示：如果喜欢更浓郁的口感，可以适当增加奶粉的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (295, 'ljhGcW8WzxtMbtVMF7ANoA', 4, '用勺子搅拌均匀即可饮用。

💡 提示：搅拌时要确保所有粉末完全溶解，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (296, 'I3woiwBE4YPZE0ltwhO4yc', 1, '将奇亚籽放入碗中，加入牛奶浸泡10分钟。

💡 提示：奇亚籽会吸收牛奶膨胀，增加口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (297, 'I3woiwBE4YPZE0ltwhO4yc', 2, '在奇亚籽浸泡的同时，将芒果去皮切丁，葡萄柚去皮去白膜切丁，备用。

💡 提示：芒果和葡萄柚切丁要均匀，大小适中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (298, 'I3woiwBE4YPZE0ltwhO4yc', 3, '取半粒芒果切成小块，与冰块和椰奶一起放入调理机中，打成泥状。

💡 提示：打成泥时可以适当调整椰奶的量，使泥状物顺滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (299, 'I3woiwBE4YPZE0ltwhO4yc', 4, '将泡好的奇亚籽倒入杯中，再依次加入芒果丁和葡萄柚丁。

💡 提示：先放奇亚籽，再放水果丁，这样层次分明。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (300, 'I3woiwBE4YPZE0ltwhO4yc', 5, '将打好的芒果椰奶泥倒入杯中，轻轻搅拌一下。

💡 提示：轻轻搅拌可以使各种材料混合均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (301, 'I3woiwBE4YPZE0ltwhO4yc', 6, '最后可以在顶部撒上一些切丝芒果干和切丝柳橙干作为点缀。

💡 提示：点缀材料可以根据个人喜好添加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (302, '7e5L8xqWrXbLYouRi8N0Ff', 1, '取一个大容器，倒入1177毫升的饮用水。

💡 提示：确保容器干净无异味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (303, '7e5L8xqWrXbLYouRi8N0Ff', 2, '加入60克酸梅晶固体饮料，使用汤匙顺时针搅拌至完全溶解。

💡 提示：分次加入可以更好地溶解', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (304, '7e5L8xqWrXbLYouRi8N0Ff', 3, '再加入剩下的60克酸梅晶固体饮料，继续使用汤匙顺时针搅拌至完全溶解。

💡 提示：确保所有颗粒都溶解，避免结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (305, '7e5L8xqWrXbLYouRi8N0Ff', 4, '加入9克方糖，使用汤匙顺时针搅拌至完全溶解。

💡 提示：方糖可以根据个人口味调整用量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (306, '7e5L8xqWrXbLYouRi8N0Ff', 5, '加入48毫升北京二锅头酒，使用汤匙顺时针搅拌均匀。

💡 提示：如果不喜欢酒精味道，可以省略此步骤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (307, '56yPgv2ZADzgaMOSUdXqCR', 1, '将柠檬对半切开，用榨汁器挤出30ml柠檬汁，过滤掉果肉和籽。

💡 提示：确保柠檬汁中没有果肉和籽，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (308, '56yPgv2ZADzgaMOSUdXqCR', 2, '在高球杯中依次加入15ml金酒、15ml龙舌兰酒、15ml伏特加、15ml白朗姆酒、15ml橙味甜酒。

💡 提示：每种酒液倒入时尽量缓慢，避免溅出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (309, '56yPgv2ZADzgaMOSUdXqCR', 3, '向杯中缓慢倒入20ml枫糖浆，边倒边用吧勺轻轻搅拌均匀。

💡 提示：枫糖浆可以增加甜味，如果不喜欢太甜可以减少用量或不加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (310, '56yPgv2ZADzgaMOSUdXqCR', 4, '加入75ml冷藏过的可乐。

💡 提示：使用冷藏过的可乐可以使饮品更加清凉爽口。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (311, '56yPgv2ZADzgaMOSUdXqCR', 5, '向杯中加入大块冰块直至满杯。

💡 提示：大块冰块融化较慢，能更好地保持饮品的冷度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (312, '56yPgv2ZADzgaMOSUdXqCR', 6, '用吧勺轻轻旋转搅拌20秒，使所有成分充分混合。

💡 提示：旋转搅拌可以使饮品更加均匀，口感更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (313, '56yPgv2ZADzgaMOSUdXqCR', 7, '开始享用。

💡 提示：建议尽快饮用，以保证最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (314, 'EZf5olwznwQX6Rnbq3dMTY', 1, '鸭肉清洗一遍放进锅中，加清水淹没鸭肉，加入20 ml料酒、1根大葱和2厘米拍散的生姜。开火烧滚，捞出浮沫，鸭肉捞出后用清水洗干净备用。

💡 提示：焯水可以去除鸭肉的腥味和血水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (315, 'EZf5olwznwQX6Rnbq3dMTY', 2, '锅清洗干净烧热，加入60 ml花生油，油温到60度时加入30颗花椒，炒出香味。

💡 提示：花椒可以增加菜肴的香气', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (316, 'EZf5olwznwQX6Rnbq3dMTY', 3, '加入鸭肉翻炒4分钟，然后加入所有的香料（草果、桂皮、八角、香叶、干辣椒）继续翻炒2分钟。

💡 提示：香料要先炒出香味再加入鸭肉', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (317, 'EZf5olwznwQX6Rnbq3dMTY', 4, '加入所有料头（生姜、大蒜、小米辣），翻炒均匀。

💡 提示：料头要最后加入，以免炒糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (318, 'EZf5olwznwQX6Rnbq3dMTY', 5, '倒入1000 ml啤酒，大火烧开后转小火慢炖30分钟。

💡 提示：啤酒可以使鸭肉更加鲜嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (319, 'EZf5olwznwQX6Rnbq3dMTY', 6, '炖煮10分钟后，加入3克盐、10 ml生抽和5 ml老抽调味。

💡 提示：调味品要分次加入，以确保味道均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (320, 'EZf5olwznwQX6Rnbq3dMTY', 7, '炖煮20分钟后，加入青椒和红椒段，继续炖煮。

💡 提示：青椒和红椒可以增加菜肴的颜色和口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (321, 'EZf5olwznwQX6Rnbq3dMTY', 8, '炖煮29分钟后，加入蒜苗段和大葱段，翻炒1分钟。

💡 提示：蒜苗和大葱段要在最后加入，以保持脆嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (322, 'EZf5olwznwQX6Rnbq3dMTY', 9, '观察汤汁，如需收汁可适当加大火力，待汤汁浓稠后即可出锅。

💡 提示：收汁可以使菜肴更加浓郁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (323, 'cDobtnqaJQdNObSnjl7uH9', 1, '将蒜和姜扒皮并剁碎备用。八角、桂皮、香叶、山奈、白蔻、小茴香洗净备用。

💡 提示：确保所有香料干净无杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (324, 'cDobtnqaJQdNObSnjl7uH9', 2, '干辣椒剪成2厘米的小段，洗净备用。

💡 提示：剪好的辣椒段要沥干水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (325, 'cDobtnqaJQdNObSnjl7uH9', 3, '小葱/大葱/洋葱洗净，洋葱切成小块。

💡 提示：洋葱切块时尽量保持均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (326, 'cDobtnqaJQdNObSnjl7uH9', 4, '兔肉剁成2厘米的小块，加入盐、料酒、味精调味，腌制15分钟。

💡 提示：腌制时间不宜过长，以免肉质变硬', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (327, 'cDobtnqaJQdNObSnjl7uH9', 5, '锅中倒入食用油，油温升至4成热（约120°C）时下入小葱/大葱/洋葱，中小火煸炒出香味，待到小葱/大葱/洋葱微焦，将其捞出。

💡 提示：注意控制火候，避免炸糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (328, 'cDobtnqaJQdNObSnjl7uH9', 6, '开大火升高油温至8成热（约240°C），下入兔肉，炸制过程转中小火，炸至兔肉微微焦黄时捞出兔肉。

💡 提示：油量应淹没兔肉，若未淹没需及时补充', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (329, 'cDobtnqaJQdNObSnjl7uH9', 7, '升高油温，倒入干辣椒、青花椒、八角、桂皮、香叶、山奈、白蔻、小茴香；转小火将辣椒段炸脆。

💡 提示：辣椒极容易炸糊，一定要小火慢炸', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (330, 'cDobtnqaJQdNObSnjl7uH9', 8, '重新倒入兔肉，加入蚝油，翻炒几分钟。

💡 提示：翻炒均匀，使兔肉充分吸收调料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (331, 'cDobtnqaJQdNObSnjl7uH9', 9, '关火，加入蒜、姜、白芝麻，翻炒均匀。

💡 提示：利用余温翻炒，避免烧焦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (332, 'cDobtnqaJQdNObSnjl7uH9', 10, '放置一夜更加入味。

💡 提示：冷藏保存，第二天食用风味更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (333, 'xmiOeSioiSLBwcZ6JMYCEx', 1, '将鸡翅放入锅中，倒入冷水淹没。加入1片生姜和10-20毫升料酒。大火煮开（约2分钟），撇去浮沫，沥干水分。

💡 提示：这一步是为了去除鸡翅的血水和杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (334, 'xmiOeSioiSLBwcZ6JMYCEx', 2, '捞出鸡翅，用刀在鸡翅两面各划两刀。用10克生抽腌制鸡翅10分钟。

💡 提示：改刀可以让鸡翅更入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (335, 'xmiOeSioiSLBwcZ6JMYCEx', 3, '锅中倒入少量油，小火加热后放入剩余的姜片爆香。然后放入腌好的鸡翅，煎至两面金黄（每面约3-4分钟）。翻动鸡翅与姜片一起炒4-5下。

💡 提示：小火慢煎可以使鸡翅表面更加酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (336, 'xmiOeSioiSLBwcZ6JMYCEx', 4, '倒入500ml可乐没过鸡翅，大火煮沸后撇去浮沫。加入葱结。

💡 提示：撇去浮沫可以使汤汁更清澈', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (337, 'xmiOeSioiSLBwcZ6JMYCEx', 5, '加入2克盐、10克白糖、3克生抽和3克老抽调味。转中火继续慢煮。

💡 提示：中火慢煮可以使鸡翅更加入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (338, 'xmiOeSioiSLBwcZ6JMYCEx', 6, '待葱结变黄，捞出葱结和姜片。转小火收汁，直到汤汁变得浓稠并能挂在鸡翅上。

💡 提示：收汁时要不断翻动鸡翅，防止糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (339, 'xmiOeSioiSLBwcZ6JMYCEx', 7, '关火，将鸡翅装盘，撒上少许葱花点缀。

💡 提示：撒上葱花可以增加菜品的香气和美观度', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (340, 'GwVNrLB3XNLsGjLrWkX7MA', 1, '将梅头猪肉（300克）洗净，然后用厨房纸抹干水分，切成约2厘米见方的小块。

💡 提示：切好的肉块大小要均匀，这样炸的时候熟度一致', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (341, 'GwVNrLB3XNLsGjLrWkX7MA', 2, '用盐（1/2茶匙）腌制梅头猪肉20分钟。

💡 提示：腌制时间不宜过长，以免肉质变硬', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (342, 'GwVNrLB3XNLsGjLrWkX7MA', 3, '将青椒（75克）切碎，菠萝片（225克）切件备用。

💡 提示：青椒和菠萝切得大小适中，与肉块搭配美观', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (343, 'GwVNrLB3XNLsGjLrWkX7MA', 4, '在碗中加入茄汁（12汤匙）、白醋（6茶匙）、蒜蓉（3汤匙）、生抽（1.5茶匙）、生粉（1.5汤匙）、白砂糖（6汤匙）、盐（1/4茶匙）和水（600毫升），拌匀成酱汁。

💡 提示：酱汁要充分搅拌均匀，确保没有结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (344, 'GwVNrLB3XNLsGjLrWkX7MA', 5, '将腌好的梅头猪肉粒沾上生粉（6汤匙），使其表面均匀裹上一层薄薄的生粉。

💡 提示：裹粉时可以轻轻拍打肉块，使生粉更好地附着', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (345, 'GwVNrLB3XNLsGjLrWkX7MA', 6, '锅中加入油（500毫升），中火加热至160℃左右，将裹好生粉的梅头猪肉粒放入锅中，中火炸5分钟，捞出沥油。

💡 提示：油温不宜过高，以免外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (346, 'GwVNrLB3XNLsGjLrWkX7MA', 7, '将油温升至180℃，将已炸好的梅头猪肉粒再次放入锅中，大火复炸1分钟，捞出沥油。

💡 提示：复炸可以使肉块更加酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (347, 'GwVNrLB3XNLsGjLrWkX7MA', 8, '锅中留少许底油（约1茶匙），倒入调好的酱汁，中火加热3分钟，直至酱汁浓稠。

💡 提示：酱汁煮至浓稠时，注意不要糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (348, 'GwVNrLB3XNLsGjLrWkX7MA', 9, '加入青椒和菠萝，大火翻炒2分钟。

💡 提示：快速翻炒，保持青椒和菠萝的脆嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (349, 'GwVNrLB3XNLsGjLrWkX7MA', 10, '最后将炸好的梅头猪肉粒加入锅中，迅速翻炒均匀，使肉块充分裹上酱汁即可出锅。

💡 提示：翻炒要快，避免肉块吸水变软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (350, '8zJWvn0P5pgV4MZIkXPx5d', 1, '将带皮猪五花肉刮洗干净，放入煮锅中，加入足够的水，大火煮沸后转小火煮约30分钟至六成熟（变色为白），捞出趁热用蜂蜜、醋涂抹肉皮。

💡 提示：煮肉时要保持水温，避免肉质过老', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('8zJWvn0P5pgV4MZIkXPx5d', 2, '炒锅内放入熟猪油，用旺火烧至八成热（约200度，油表有大量青烟，油状平静），将肉块皮朝下投入，炸至呈金红色时（约3-5分钟），捞入凉肉煮锅（之前煮完的煮锅）中泡软（约10分钟），放在案板上，切成三寸(10 cm)长、两分(0.6 cm);

💡 提示：炸肉时注意安全，防止油溅；泡软时间不宜过长，以免肉质过软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (352, '8zJWvn0P5pgV4MZIkXPx5d', 3, '将5克大葱切成2.4 cm长的段，5克切成2.4 cm长的斜形片。姜去皮洗净，1.5克切成片，5克切成末，摊制的鸡蛋皮切成2.4 cm长的等腰三角形片。

💡 提示：切葱姜时尽量均匀，以便调味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (353, '8zJWvn0P5pgV4MZIkXPx5d', 4, '商芝入沸水锅中煮软捞出，去除老茎、杂质，淘洗干净，切成3 cm长的段，放入碗中,加酱油（5克）、精盐（1克）、熟猪油（10克）拌匀，盖在肉片上。另将鸡汤（100克）放入一小碗中，加酱油（5克）、精盐（0.5克）、料酒（15克）搅匀，浇入蒸碗，再放入姜片、葱段、八角上笼用旺火蒸约半小时后，转用小火继续蒸约一小时三十分钟，熟烂后取出，拣去姜、葱、八角，倒、过滤原汁，将肉扣入汤盘。

💡 提示：蒸制过程中注意火候，先旺火后小火，使肉质更加酥烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (354, '8zJWvn0P5pgV4MZIkXPx5d', 5, '炒锅内，放入剩余的鸡汤（100克），加入原汁，用旺火烧沸，下入姜末、葱片、味精后搅匀，投入摊制的鸡蛋皮，淋芝麻油，浇入汤盘即成。

💡 提示：最后一步调味要快，保持汤汁的鲜美', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (355, '1LwioNB1bb4C8oHgwEO49y', 1, '将小米椒切碎，和孜然粒一起放入捣药罐捣碎成颗粒。如果时间紧张可跳过捣碎步骤。

💡 提示：捣碎后的孜然和小米椒更易入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (356, '1LwioNB1bb4C8oHgwEO49y', 2, '青椒切头去籽（喜欢辣的可不去），切成丝。葱切段。

💡 提示：青椒切丝时尽量保持粗细均匀，以便炒制时受热均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (357, '1LwioNB1bb4C8oHgwEO49y', 3, '牛肉提前解冻，过一遍水洗干净，晾干或用厨用纸吸干，将牛肉顺着纹理切成片。

💡 提示：顺着纹理切片可以使牛肉更加嫩滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (358, '1LwioNB1bb4C8oHgwEO49y', 4, '将切好的牛肉加入生抽、淀粉、油，均匀搅拌后静置腌制30分钟。

💡 提示：腌制时可以将牛肉放入冰箱冷藏，使肉质更加紧实', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (359, '1LwioNB1bb4C8oHgwEO49y', 5, '热锅下油，放入葱段，爆出香味后放入腌好的牛肉煸炒。

💡 提示：火候要大，快速翻炒以锁住肉汁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (360, '1LwioNB1bb4C8oHgwEO49y', 6, '待牛肉变色后，均匀撒入孜然辣椒颗粒并炒熟。

💡 提示：孜然和辣椒颗粒要均匀撒在牛肉上，使其充分吸收香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (361, '1LwioNB1bb4C8oHgwEO49y', 7, '下入青椒丝，断生后放盐，大火炒1分钟后关火再翻炒30秒，保证受热均匀即可出锅。

💡 提示：青椒不宜炒太久，以免失去脆嫩口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (362, 'Y5tNfPJr4ZriE5wNU0m7IM', 1, '将五花肉切成薄片，厚度约2mm。

💡 提示：切片时尽量保持均匀，以便烹饪时受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (363, 'Y5tNfPJr4ZriE5wNU0m7IM', 2, '将切好的五花肉放入碗中，加入淀粉、老抽和盐，搅拌均匀后腌制半小时。

💡 提示：腌制时间越长，肉质越入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (364, 'Y5tNfPJr4ZriE5wNU0m7IM', 3, '将葱切段，小米椒和朝天椒斜刀切好，蒜切片备用。

💡 提示：辣椒斜刀切可以更好地释放辣味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (365, 'Y5tNfPJr4ZriE5wNU0m7IM', 4, '热锅，倒入食用油，待油温升至6成热（约180℃）时，加入腌制好的五花肉煸炒。

💡 提示：油温不宜过高，以免外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (366, 'Y5tNfPJr4ZriE5wNU0m7IM', 5, '炒至五花肉变色且表面微焦时，盛出备用。

💡 提示：注意观察肉的颜色变化，避免炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (367, 'Y5tNfPJr4ZriE5wNU0m7IM', 6, '锅中留少许底油，加入蒜片，煸炒出香味后加入豆豉，翻炒均匀。

💡 提示：豆豉要炒出香味，但不要炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (368, 'Y5tNfPJr4ZriE5wNU0m7IM', 7, '加入豆瓣酱，继续翻炒均匀，炒出红油。

💡 提示：豆瓣酱炒出红油后，味道更香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (369, 'Y5tNfPJr4ZriE5wNU0m7IM', 8, '将炒好的五花肉重新倒入锅中，翻炒均匀，使肉片充分吸收调料的味道。

💡 提示：快速翻炒，使肉片均匀裹上调料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (370, 'Y5tNfPJr4ZriE5wNU0m7IM', 9, '加入小米椒、朝天椒和葱段，大火快速翻炒40秒。

💡 提示：大火快炒可以保持辣椒的脆爽口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (371, 'Y5tNfPJr4ZriE5wNU0m7IM', 10, '出锅装盘，即可享用。

💡 提示：趁热食用，风味更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (372, 'DOcyLI8aosg02uTeSoA7M1', 1, '将小米辣洗净，斜刀切成大段备用。

💡 提示：斜刀切可以使小米辣更入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (373, 'DOcyLI8aosg02uTeSoA7M1', 2, '将五花肉或瘦肉切成薄片或丝，加入生抽、蚝油、盐腌制5分钟。

💡 提示：腌制时间不宜过长，以免肉质变老', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (374, 'DOcyLI8aosg02uTeSoA7M1', 3, '热锅倒入花生油，中火加热至油温六成热时，下入腌好的肉片，快速翻炒至变色后盛出备用。

💡 提示：肉片不要炒得太久，以免变老', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (375, 'DOcyLI8aosg02uTeSoA7M1', 4, '锅中留底油，放入切好的姜蒜片爆香，再加入豆瓣酱，小火炒至红油出来。

💡 提示：炒豆瓣酱时要小火慢炒，避免糊锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (376, 'DOcyLI8aosg02uTeSoA7M1', 5, '倒入切好的小米辣，大火快速翻炒均匀，然后加入之前炒好的肉片，继续翻炒均匀。

💡 提示：大火快炒可以保持食材的口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (377, 'DOcyLI8aosg02uTeSoA7M1', 6, '最后加入生抽、鸡精、白糖调味，快速翻炒均匀即可出锅。

💡 提示：调味料要最后加入，以免影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (378, 'Z3eWrLa4t24XnZHlMZA6Xl', 1, '制作葱姜水：将老姜丝、小葱段、料酒、清水放入碗中，用手捏揉5分钟，至液体泛白、散发浓郁辛香。

💡 提示：务必充分揉压，释放姜葱汁液；静置5分钟再使用效果更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (379, 'Z3eWrLa4t24XnZHlMZA6Xl', 2, '处理猪肉：猪肉去皮洗净，切成8–10 cm长、1.5 cm厚的肉条。

💡 提示：刀工均匀利于受热一致；切后可用厨房纸吸干表面水分。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (380, 'Z3eWrLa4t24XnZHlMZA6Xl', 3, '腌制：将肉条放入大碗，加入盐、十三香、胡椒粉、味精、鸡精、花椒碎、花椒粒、生抽，倒入葱姜水，抓匀后用力揉搓10分钟，直至肉条粘手、水分完全吸收。

💡 提示：揉制是入味关键；务必戴手套操作更卫生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (381, 'Z3eWrLa4t24XnZHlMZA6Xl', 4, '冷藏静置：封保鲜膜，放入冰箱冷藏30分钟。

💡 提示：低温帮助肉质收紧、调料渗透，提升嫩度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (382, 'Z3eWrLa4t24XnZHlMZA6Xl', 5, '裹粉：将冷藏好的肉条取出，加入面粉、红薯淀粉及2个鸡蛋的蛋清（蛋黄另存），充分揉搓15分钟，使粉浆均匀包裹并呈柔韧粘附状态，无干粉颗粒。

💡 提示：红薯淀粉必须过筛；若粉团过干可滴加少量清水（≤5 ml），勿多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (383, 'Z3eWrLa4t24XnZHlMZA6Xl', 6, '初炸定型：锅中倒入足量植物油（油面高度≥3 cm），大火加热至油温150°C（插入竹筷周边有细密气泡），转小火维持温度；逐条下入肉条，用筷子轻捋成直条或微弯状，中小火炸3–5分钟至微黄色、略硬挺，捞出沥油。

💡 提示：分批下锅防粘连；新手建议单条试炸掌握火候；炸后平铺晾凉勿堆叠。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (384, 'Z3eWrLa4t24XnZHlMZA6Xl', 7, '复炸上色：将油温升至180°C（竹筷插入剧烈冒泡），倒入初炸肉条，炸1–2分钟至整体金黄酥脆，迅速捞出沥油。

💡 提示：复炸时间短、火力高，务必守锅防焦；可轻敲听声判断酥脆度（空响即熟）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (385, 'yMq7v8xmqsxW1JFQlNV8Wt', 1, '将牛肉切成薄片，放入碗中。加入姜片、盐、酱油和糖进行腌制，腌制时间30-40分钟。

💡 提示：腌制时可以加入少量小苏打使牛肉更嫩滑，但不要过量，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (386, 'yMq7v8xmqsxW1JFQlNV8Wt', 2, '腌制好的牛肉去掉姜片备用。葱切段，姜切片，蒜剁成蒜泥，尖椒切成段。

💡 提示：尖椒切段时尽量保持均匀，以便烹饪时受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (387, 'yMq7v8xmqsxW1JFQlNV8Wt', 3, '锅中倒入适量油，冷油下锅，待油温升至五成热（约150℃），偶有气泡时加入蒜泥。

💡 提示：油温不宜过高，以免蒜泥焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (388, 'yMq7v8xmqsxW1JFQlNV8Wt', 4, '蒜泥变金黄后加入尖椒翻炒，待尖椒表皮微皱时加入腌制好的牛肉快速翻炒。

💡 提示：牛肉下锅后要快速翻炒，避免粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (389, 'yMq7v8xmqsxW1JFQlNV8Wt', 5, '牛肉变色后加入葱段，继续翻炒至牛肉完全变熟，关火出锅。

💡 提示：牛肉变色即为半熟，再翻炒几下即可，避免过度烹饪导致肉质变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (390, 'cLASPsuC6FJEmUJLcFqMyL', 1, '将木耳提前泡发好，如果着急可以用热水泡发。

💡 提示：确保木耳完全泡发，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (391, 'cLASPsuC6FJEmUJLcFqMyL', 2, '将猪里脊切成薄片放入碗中，加入20ml生抽、10ml料酒、适量花椒粉，打入一个鸡蛋，用手搅拌均匀，再加入10g淀粉拌匀，倒入300ml食用油封浆，腌制15分钟。

💡 提示：腌制时要充分搅拌，使肉片均匀裹上蛋液和淀粉。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (392, 'cLASPsuC6FJEmUJLcFqMyL', 3, '将蒜苔切段大约3cm，葱头切菱形块备用。

💡 提示：切好的蒜苔和葱头可以用水稍微冲洗一下，去除多余水分。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (393, 'cLASPsuC6FJEmUJLcFqMyL', 4, '起锅烧油，油温五成热（约150℃），下入腌制好的肉片，将肉片打散，炸至表面微焦，捞出控油备用。

💡 提示：注意控制火候，避免肉片炸糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (394, 'cLASPsuC6FJEmUJLcFqMyL', 5, '将锅中多余的油倒出，留10ml油炒菜，油温七成热（约210℃）。

💡 提示：油温高一些可以使食材快速炒熟，保持脆嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (395, 'cLASPsuC6FJEmUJLcFqMyL', 6, '下入葱姜蒜爆香，先下蒜苔炒至断生，再下入木耳和葱头，加入20ml生抽，适量花椒粉，翻炒几下。

💡 提示：蒜苔炒至断生即可，不要炒得太软。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (396, 'cLASPsuC6FJEmUJLcFqMyL', 7, '将之前炸好的肉片下入锅中，翻炒均匀，加10g盐调味。

💡 提示：肉片回锅后要快速翻炒，避免肉片变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (397, 'cLASPsuC6FJEmUJLcFqMyL', 8, '起锅前加入10ml陈醋和适量鸡精，翻炒均匀后起锅装盘。

💡 提示：起锅前加醋可以提味，但不要加太多，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (398, 'p7MAVXCgBqIGGeMqA15HP7', 1, '将肘子刮洗干净，肘头朝外、肘把（脚爪）朝里、肘皮朝下放在案板上。

💡 提示：确保肘子表面干净无杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (399, 'p7MAVXCgBqIGGeMqA15HP7', 2, '用刀在正中由肘头向肘把沿着腿骨将皮剖开，剔去腿骨两边的肉（三面离肉），底部骨与肉相连，使骨头露出，然后用小斧头将两节腿骨砸断。

💡 提示：小心操作，避免伤手', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (400, 'p7MAVXCgBqIGGeMqA15HP7', 3, '将处理好的肘子放入锅中，加入足够的水，大火煮沸后转中小火煮约1.5小时，至七成熟捞出（外观正常，内部淡红色）。

💡 提示：煮至七成熟时，可以用筷子插入肘子最厚处，能轻松插入即为合适', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (401, 'p7MAVXCgBqIGGeMqA15HP7', 4, '用干净抹布擦干肘子表面水分，趁热用红酱油涂抹肉皮。

💡 提示：涂抹均匀，使肉皮上色', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (402, 'p7MAVXCgBqIGGeMqA15HP7', 5, '取一个蒸锅，锅底放入八角、桂皮，先将肘把的关节处用手掰断，不伤外皮，再将肘皮朝下装进蒸锅内，装锅时根据肘子体型，将肘把贴住锅边窝着装进锅内，成为圆形。

💡 提示：确保肘子摆放稳固', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (403, 'p7MAVXCgBqIGGeMqA15HP7', 6, '撒入精盐，用消过毒的干净纱布盖在肉上，再将甜面酱（50克）、葱（75克）、红豆腐乳、红酱油、白酱油、姜、蒜等在纱布上抹开。

💡 提示：纱布消毒方法：用开水煮沸10分钟后晾干', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (404, 'p7MAVXCgBqIGGeMqA15HP7', 7, '用旺火蒸大约3小时，直至肘子完全熟透、酥烂。

💡 提示：蒸锅下半放水，上半放肘子，蒸时及时加水防止蒸干', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (405, 'p7MAVXCgBqIGGeMqA15HP7', 8, '蒸完取出，揭去纱布，扣入盘中，拣去八角，上桌时另带葱段和甜面酱小碟（或将甜面酱抹到肘面上，另带葱段小碟亦可）。

💡 提示：注意不要烫伤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (406, '6X3YkDcPAiwNLvrdzqI23k', 1, '将鸡腿肉清洗干净，用厨房纸巾擦干水分。

💡 提示：确保鸡肉表面干燥，有助于腌制入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (407, '6X3YkDcPAiwNLvrdzqI23k', 2, '在鸡腿肉上均匀涂抹盐、黑胡椒、橄榄油和蒜末，腌制10分钟。

💡 提示：腌制时间越长，味道越入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (408, '6X3YkDcPAiwNLvrdzqI23k', 3, '预热烤箱至180度。

💡 提示：预热烤箱可以保证鸡肉受热均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (409, '6X3YkDcPAiwNLvrdzqI23k', 4, '将腌好的鸡腿肉放入烤盘中，放入预热好的烤箱中层，烤30-40分钟或至熟透。

💡 提示：中途可翻面一次，使两面都烤得金黄酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (410, '6X3YkDcPAiwNLvrdzqI23k', 5, '烤制期间，将欧芹切成碎末备用。

💡 提示：切碎的欧芹可以增加菜品的香气和颜色', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (411, '6X3YkDcPAiwNLvrdzqI23k', 6, '将柠檬挤出汁备用。

💡 提示：新鲜柠檬汁可以提升鸡肉的清新口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (412, '6X3YkDcPAiwNLvrdzqI23k', 7, '烤好的鸡肉取出，淋上柠檬汁，撒上欧芹碎即可。

💡 提示：趁热食用，口感更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (413, '37jLPV5JefXrr4vsI1r0sK', 1, '将血肠用牙签多扎一些小孔，然后放入锅中，加入足够的水，用小火煮10分钟，保持水温在80度左右，防止血肠爆开。

💡 提示：小火慢煮可以避免血肠爆裂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (414, '37jLPV5JefXrr4vsI1r0sK', 2, '将煮好的血肠捞出，切成块状备用。

💡 提示：切块时注意不要切得太厚', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (415, '37jLPV5JefXrr4vsI1r0sK', 3, '将排骨放入锅中，加入料酒，大火焯水，去除血沫后捞出，控干水分备用。

💡 提示：焯水可以去除排骨的腥味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (416, '37jLPV5JefXrr4vsI1r0sK', 4, '锅内放入菜籽油，加入蒜瓣、干辣椒和姜粉，小火炒香。

💡 提示：小火炒香可以更好地释放香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (417, '37jLPV5JefXrr4vsI1r0sK', 5, '将焯好水的排骨放入锅中，翻炒至表面金黄。

💡 提示：翻炒至表面微焦，增加口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (418, '37jLPV5JefXrr4vsI1r0sK', 6, '将洗净并拧干水分的酸菜放入锅中，加入香油，大火翻炒2分钟。

💡 提示：香油可以去除酸菜的酸味，增加香气', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (419, '37jLPV5JefXrr4vsI1r0sK', 7, '加入600毫升热水，转入电压力锅，加入香叶、八角、葱结和盐。

💡 提示：确保所有调料均匀分布', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (420, '37jLPV5JefXrr4vsI1r0sK', 8, '使用电压力锅的浓香模式，压40分钟。如果没有电压力锅，可以用普通锅具，小火炖煮1小时。

💡 提示：电压力锅可以更快地炖煮食材，保留更多营养', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (421, '37jLPV5JefXrr4vsI1r0sK', 9, '到时间后放气开盖，加入切好的血肠和适量枸杞，盖上锅盖焖2分钟即可。

💡 提示：血肠已经煮熟，不需要再加热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (422, '37jLPV5JefXrr4vsI1r0sK', 10, '将炖好的杀猪菜倒入盆中，调制蘸料（辣椒油 5 克、生抽 10 克、蒜蓉 5 克、香油 2 克），即可享用。

💡 提示：蘸料可以根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (423, '2TdbPEWosACjPHZSjMq5yY', 1, '将大排洗净，剔去骨头，用刀背拍松，切成厚片，再改切成粗条。

💡 提示：拍松可以使肉质更嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (424, '2TdbPEWosACjPHZSjMq5yY', 2, '在切好的排条中加入椒盐粉，搅拌均匀，待到出胶质后分次加入葱姜水，放入冰箱腌制20分钟。

💡 提示：腌制时间不宜过长，以免肉质变硬', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (425, '2TdbPEWosACjPHZSjMq5yY', 3, '制作炸糊。在一个大碗中放入80克面粉、20克淀粉、2-3克吉士粉和1克盐，打入一个鸡蛋，搅拌均匀。

💡 提示：搅拌时要确保所有干粉都充分混合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (426, '2TdbPEWosACjPHZSjMq5yY', 4, '分次加入100克水，再加入10克油，反复搅拌至炸糊完全调开，略粘稠即可。

💡 提示：炸糊的稠度要适中，太稀容易脱浆，太稠则不易挂糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (427, '2TdbPEWosACjPHZSjMq5yY', 5, '取出剩余的60克淀粉，将腌好的排条先裹上一层淀粉，再裹上面糊。

💡 提示：先裹淀粉再裹面糊可以使炸出来的排条更加酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (428, '2TdbPEWosACjPHZSjMq5yY', 6, '锅中加入足够的油，加热至150℃-160℃，下入排条炸至浅金黄色后捞出。

💡 提示：刚下锅时不要动排条，待定型后再翻动', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (429, '2TdbPEWosACjPHZSjMq5yY', 7, '待油温再次升高到150℃-160℃时，下入排条复炸至金黄色后捞出。

💡 提示：复炸可以使排条更加酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (430, '2TdbPEWosACjPHZSjMq5yY', 8, '将炸好的排条放在厨房纸上吸去多余的油，撒上椒盐粉，搅拌均匀后出锅。

💡 提示：撒椒盐粉时要均匀，避免过多或过少', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (431, 'oM16wT3cZmCLmkWbRGLhIE', 1, '里脊肉切2毫米薄片，清水淘洗2遍去血水，捞出挤干水分。

💡 提示：务必挤干水分，否则影响腌制效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (432, 'oM16wT3cZmCLmkWbRGLhIE', 2, '肉片加1.5g盐、1g胡椒粉、5g生抽、3g料酒，朝同一方向搅拌2分钟至发黏入味。

💡 提示：单向搅拌可增强肉质保水性。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (433, 'oM16wT3cZmCLmkWbRGLhIE', 3, '另取碗，将1个鸡蛋清与7g土豆淀粉搅匀成糊，倒入肉片中，继续单向搅拌至均匀上浆。

💡 提示：形成润滑膜是肉片滑嫩的关键。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (434, 'oM16wT3cZmCLmkWbRGLhIE', 4, '加入30g植物油轻轻拌匀，防止下锅粘连。腌制静置15分钟。

💡 提示：油封可锁住水分，提升嫩度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (435, 'oM16wT3cZmCLmkWbRGLhIE', 5, '豆芽、凤尾、芹菜、蒜苗分别处理：豆芽洗净；凤尾切条；芹菜切段；蒜苗拍散后切段。

💡 提示：配菜宜保持脆嫩，不宜过早切配。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (436, 'oM16wT3cZmCLmkWbRGLhIE', 6, '大蒜20g、生姜10g、红泡椒20g剁碎备用。

💡 提示：姜蒜蓉越细，爆香越充分。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (437, 'oM16wT3cZmCLmkWbRGLhIE', 7, '锅中倒适量油烧热，下15g干辣椒段和3g青花椒，小火炸至颜色微深（勿焦黑），捞出剁细成刀口辣椒。

💡 提示：全程小火，离火余温仍会继续加热，防糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (438, 'oM16wT3cZmCLmkWbRGLhIE', 8, '锅烧热，放100g植物油至六成热（约160℃），下干辣椒段、3g青花椒爆香，随即下豆芽、凤尾、芹菜、蒜苗，加1g盐，中火翻炒至断生（约2分钟），盛出铺于大碗底部。

💡 提示：蔬菜不宜炒老，保持爽脆口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (439, 'oM16wT3cZmCLmkWbRGLhIE', 9, '洗净锅，放150g植物油烧至六成热，下姜蒜红泡椒碎爆香，加10g红油豆瓣酱，小火炒出红油（约3分钟）。

💡 提示：豆瓣必须炒透去生味、激发出红油才够香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (440, 'oM16wT3cZmCLmkWbRGLhIE', 10, '加入800ml清水，大火烧开后转小火，加2.5g盐、1.5g鸡精、1g白糖、1g胡椒粉调味；可选加5g水淀粉（淀粉+等量水调匀）勾薄芡使汤汁略浓。

💡 提示：水淀粉宜最后淋入，边搅边加，防结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (441, 'oM16wT3cZmCLmkWbRGLhIE', 11, '汤微沸（非滚沸）时，将肉片分散下锅，中火烫煮约1.5–2分钟至变色熟透，轻推防粘，捞出铺于碗中蔬菜上，再将热汤滤净浮沫后倒入，液面不没过食材。

💡 提示：火候宁小勿大，避免肉片变柴；切忌滚沸猛煮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (442, 'oM16wT3cZmCLmkWbRGLhIE', 12, '在肉片表面均匀撒上步骤7制的刀口辣椒、剩余蒜蓉（约5g）、小葱花。

💡 提示：葱蒜现撒，泼油后香气更足。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (443, 'oM16wT3cZmCLmkWbRGLhIE', 13, '洗净锅，倒入200g菜籽油，烧至七成热（约180℃，油面微有青烟），离火稍稳2秒，迅速均匀泼在碗中配料上。

💡 提示：务必确保油温足够高，才能激发出辣椒与花椒的复合香气；注意防溅烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (444, 'PnXSwmzyF8IZ48Y27yoTdD', 1, '洋葱切成薄片，猪肉切成薄片，蒜头拍碎备用。将酱油、糖、麻油、番茄酱和料酒混合均匀备用。

💡 提示：洋葱切片要尽量均匀，以便炒制时熟度一致。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (445, 'PnXSwmzyF8IZ48Y27yoTdD', 2, '炒锅内倒入1大匙食用油，开中火加热10秒左右，待油温升高后，加入猪肉片快速翻炒至变色。

💡 提示：猪肉片下锅后要迅速翻炒，防止粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (446, 'PnXSwmzyF8IZ48Y27yoTdD', 3, '加入拍碎的蒜头，继续翻炒几秒钟至香味四溢，然后盛起备用。

💡 提示：蒜头不要炒太久，以免焦糊影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (447, 'PnXSwmzyF8IZ48Y27yoTdD', 4, '原锅内再加少许油，放入洋葱片翻炒3-4分钟，直至洋葱变软并略微透明。

💡 提示：洋葱炒至微透明时，口感最佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (448, 'PnXSwmzyF8IZ48Y27yoTdD', 5, '将之前调好的调味料倒入锅中，与洋葱一起翻炒均匀。

💡 提示：调味料要充分拌匀，使洋葱均匀吸收味道。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (449, 'PnXSwmzyF8IZ48Y27yoTdD', 6, '最后加入炒好的猪肉片，快速翻炒1-2分钟，直至猪肉完全熟透。

💡 提示：猪肉回锅后要快速翻炒，确保肉质嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (450, 'PnXSwmzyF8IZ48Y27yoTdD', 7, '出锅前撒上黑胡椒粉，翻炒均匀后即可关火，装盘上桌。

💡 提示：黑胡椒粉可以提升整道菜的香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (451, 'TuhT4ZpgObb4e9nf9wOBQp', 1, '将鸡翅放入大碗中，加入盐、黑胡椒粉、酱油、料酒、蜂蜜、姜蒜粉和五香粉，搅拌均匀，腌制30-40分钟。

💡 提示：腌制时间越长，味道越入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (452, 'TuhT4ZpgObb4e9nf9wOBQp', 2, '预热烤箱至200℃。

💡 提示：确保烤箱充分预热，以保证烤制效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (453, 'TuhT4ZpgObb4e9nf9wOBQp', 3, '在烤盘底部铺上一层锡纸，将腌制好的鸡翅均匀地放在烤盘上。

💡 提示：使用锡纸可以防止鸡翅粘连，并便于清洁烤盘。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (454, 'TuhT4ZpgObb4e9nf9wOBQp', 4, '将烤盘放入烤箱中层，烤15-20分钟。

💡 提示：注意观察鸡翅的颜色变化，避免烤焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (455, 'TuhT4ZpgObb4e9nf9wOBQp', 5, '取出烤盘，用夹子将鸡翅翻面，再烤15-20分钟，直到鸡翅表面呈金黄色且熟透。

💡 提示：可以用筷子扎一下鸡翅最厚的部分，如果没有血水流出即表示熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (456, '0rd0ElNzk9jQ1lPSoUyraD', 1, '将大葱切段；生姜50克切段，50克切末；大蒜切末，备用。

💡 提示：切好的葱姜蒜分别放置，方便后续使用', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (457, '0rd0ElNzk9jQ1lPSoUyraD', 2, '将全部酸菜切成丝，用水冲洗2～3遍，备用。冲洗次数取决于个人口味，喜欢酸味可以冲洗2遍，害怕酸味可以冲洗3～4遍。

💡 提示：冲洗酸菜时不要过度，以免失去酸味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (458, '0rd0ElNzk9jQ1lPSoUyraD', 3, '将排骨和五花肉放入锅中，倒入冷水淹没。放入全部葱段、50克生姜段和20毫升料酒。大火煮开后，等待5分钟。关火，将排骨和五花肉捞出，用冷水冲洗掉浮沫，备用。

💡 提示：焯水可以去除血水和杂质，使肉质更加鲜美', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (459, '0rd0ElNzk9jQ1lPSoUyraD', 4, '将煮好的五花肉切片或切块，备用。

💡 提示：切片或切块可以根据个人喜好决定', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (460, '0rd0ElNzk9jQ1lPSoUyraD', 5, '将之前的锅洗干净，并且擦干（不然加入油会崩出来）。锅中加入适量油，开中火，放入姜蒜末爆香，放入五花肉和排骨。将五花肉和排骨煎至金黄，倒入10克五香粉和15克生抽酱油，用铲子翻动1～2分钟。

💡 提示：煎至金黄可以使肉质更加香脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (461, '0rd0ElNzk9jQ1lPSoUyraD', 6, '将冲洗好的酸菜丝加入锅中，翻炒3分钟。

💡 提示：翻炒均匀，使酸菜充分吸收肉香', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (462, '0rd0ElNzk9jQ1lPSoUyraD', 7, '倒入纯净水至刚好没过食材，加入2颗大料，转大火，直到锅中水沸腾。转中火，盖锅盖焖煮1.5～2小时，直至五花肉软烂（可以用筷子轻松扎穿）。

💡 提示：保持中小火，避免糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (463, '0rd0ElNzk9jQ1lPSoUyraD', 8, '掀开锅盖，开大火收汤，翻动锅中食材直至锅中剩余水分只覆盖锅底，转小火，准备调味。

💡 提示：收汤时注意不要糊锅，可以适当翻动来检查水位', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (464, '0rd0ElNzk9jQ1lPSoUyraD', 9, '调味：加入食用盐10克，搅拌均匀。

💡 提示：最后加盐时，可以一点一点加入，搅拌后品尝味道，直到可以接受的口味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (465, '0rd0ElNzk9jQ1lPSoUyraD', 10, '关火，出锅。

💡 提示：出锅前可以撒上一些葱花增加香气', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (466, 'hJu9AvT1O6T83kukUu4EMu', 1, '在鸡全翅翅中两根骨头之间用刀划开表皮，正反面各一刀。

💡 提示：便于入味和受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('hJu9AvT1O6T83kukUu4EMu', 2, '将鸡全翅放入碗中，加入生抽、老抽、蒜粉、胡椒粉、糖、甜椒粉、辣椒粉、蚝油、水和油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (468, 'hJu9AvT1O6T83kukUu4EMu', 3, '用勺子将酱汁均匀涂抹在鸡全翅上，尤其注意刀口处。

💡 提示：确保每只翅充分裹酱。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (469, 'hJu9AvT1O6T83kukUu4EMu', 4, '用保鲜膜封住碗口，放入冰箱冷藏腌制。

💡 提示：建议腌制时间60–180分钟；时间越长越入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (470, 'hJu9AvT1O6T83kukUu4EMu', 5, '取出腌好的鸡全翅，摆入锡纸盘中；将碗中剩余酱料均匀淋在鸡翅上。

💡 提示：淋酱可提升色泽与风味；若偏好浅色可省略此步。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (471, 'hJu9AvT1O6T83kukUu4EMu', 6, '将锡纸盘放入空气炸锅烤篮，200℃烘烤25分钟。

💡 提示：注意实际温度依设备功率微调。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (472, 'hJu9AvT1O6T83kukUu4EMu', 7, '取出锡纸盘，小心翻面（可用夹子防烫）。

💡 提示：使用隔热工具操作，避免烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (473, 'hJu9AvT1O6T83kukUu4EMu', 8, '放回空气炸锅，200℃继续烘烤25分钟。

💡 提示：最终呈微焦褐色；若喜浅色可减至每面20分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (474, 'g82H2WY09YkUS4PhrMvtFx', 1, '将胡萝卜、芹菜、洋葱切碎，蒜瓣切片。

💡 提示：尽量切得细碎一些，以便更好地融合在酱料中', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (475, 'g82H2WY09YkUS4PhrMvtFx', 2, '在锅中加入10ml橄榄油，加热后放入切好的蔬菜（胡萝卜、芹菜、洋葱），大火翻炒至略微变色后盛出备用。

💡 提示：炒至蔬菜略微变软即可，不要炒得太久以免失去脆感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (476, 'g82H2WY09YkUS4PhrMvtFx', 3, '在同一个锅中再加入10ml橄榄油，加热后放入蒜片翻炒10秒，然后加入碎牛肉、糖、盐、胡椒粉和香料（如果使用）。

💡 提示：炒至牛肉变色且表面略微焦脆，有颗粒感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (477, 'g82H2WY09YkUS4PhrMvtFx', 4, '将炒好的蔬菜倒回锅中，加入番茄酱，继续翻炒均匀。

💡 提示：确保所有食材充分混合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (478, 'g82H2WY09YkUS4PhrMvtFx', 5, '分3次缓缓倒入牛奶，每次倒入后搅拌均匀，中小火煮30分钟，期间不断搅动以防粘锅。

💡 提示：每次倒入牛奶后要充分搅拌，使酱料更加顺滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (479, 'g82H2WY09YkUS4PhrMvtFx', 6, '煮至酱料变得浓稠，尝一下味道并根据需要调整盐量。

💡 提示：根据个人口味调整调味品用量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (480, '3KzuGxNyq8Zrfof4M7EppC', 1, '锅内烧水，水开后放入干粉条，煮5分钟后同水一起倒出容器中，盖上盖子继续浸泡备用。粉条需提前浸泡至少30分钟。

💡 提示：粉条要提前浸泡至软，这样烹饪时更容易熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (481, '3KzuGxNyq8Zrfof4M7EppC', 2, '五花肉切3mm的肉片，备用。

💡 提示：五花肉切片要均匀，厚度适中，这样烹饪时更易入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (482, '3KzuGxNyq8Zrfof4M7EppC', 3, '大白菜嫩叶与白菜帮子分开切成2份菜片，备用。

💡 提示：白菜帮子和嫩叶分开处理，可以更好地控制烹饪时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (483, '3KzuGxNyq8Zrfof4M7EppC', 4, '热锅，锅内放入10ml - 15ml食用油。等待10秒让油温升高。

💡 提示：油温不宜过高，以免食材下锅后糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (484, '3KzuGxNyq8Zrfof4M7EppC', 5, '放入五花肉，保持翻炒至肉变色。

💡 提示：五花肉要炒至表面微黄，这样可以去除多余的油脂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (485, '3KzuGxNyq8Zrfof4M7EppC', 6, '加入老抽，炒1分钟，给肉上色。

💡 提示：老抽不要加太多，以免颜色过深。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (486, '3KzuGxNyq8Zrfof4M7EppC', 7, '加入白菜帮子，加入食用盐、生抽，炒1分钟（如果粘锅，烹入10ml水）。

💡 提示：白菜帮子较硬，需要先炒一下，使其稍微软化。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (487, '3KzuGxNyq8Zrfof4M7EppC', 8, '加水没过所有食材，加入鸡精、十三香，沸腾后，将火调小然后等待20分钟。

💡 提示：小火慢炖可以使食材更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (488, '3KzuGxNyq8Zrfof4M7EppC', 9, '粉条滤水切成小段放入碗中备用。

💡 提示：粉条切成小段更容易入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (489, '3KzuGxNyq8Zrfof4M7EppC', 10, '加入白菜嫩叶，炒匀后将粉条放在菜上方，加盖再煮5分钟。

💡 提示：白菜嫩叶容易熟，最后加入即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (490, '3KzuGxNyq8Zrfof4M7EppC', 11, '尝味、关火，收汁至汤汁浓稠。

💡 提示：收汁时要注意火候，避免糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 1, '将五花肉洗净，切成长约5cm、宽约3cm、厚度约0.5cm的肉片。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 2, '将姜、蒜切成颗粒直径不大于1mm的细末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 3, '取一大碗，放入切好的五花肉、生抽15ml、老抽10ml、料酒15ml、郫县豆瓣酱10g、姜末10g、蒜末10g、白砂糖5g，用筷子搅拌均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 4, '盖上保鲜膜，室温（20°C–25°C）静置腌制30分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 5, '腌制完成后，加入蒸肉米粉100g，继续翻拌2分钟，确保每片肉均匀裹粉。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (496, '3bfI2TEUMqAmKyppFZVBp0', 6, '土豆去皮，切片，厚度0.8cm，单片面面积约5cm×5cm，总重300g。

💡 提示：尽量无重叠铺满碗底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 7, '在直径20cm的深碗底部铺满土豆片。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 8, '将拌好粉的五花肉均匀铺在土豆片上，并轻轻压实。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (499, '3bfI2TEUMqAmKyppFZVBp0', 9, '蒸锅中加入清水2000ml，开火加热至水面持续冒泡（100°C）。

💡 提示：注意水量充足，初始水位需足够', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('3bfI2TEUMqAmKyppFZVBp0', 10, '将装好食材的碗放入蒸锅内，盖好锅盖。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (501, '3bfI2TEUMqAmKyppFZVBp0', 11, '保持中火蒸60分钟（火力维持可持续沸腾，约600W热功率）。

💡 提示：期间如水量低于锅底高度1cm，立即补充500ml 90°C以上热水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (502, '3bfI2TEUMqAmKyppFZVBp0', 12, '时间结束后，用筷子插入肉块中央：若能轻松穿透且无明显阻力，则蒸熟；否则继续蒸10–15分钟，直至肉质软烂、油脂渗出。

💡 提示：以筷子轻松穿透为成熟标准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (503, 'FBllvNtaClPwnbfWr0gQia', 1, '将猪里脊肉切成厚片，用刀背拍松，再切成手指粗的条。加入料酒、生抽、蚝油、食盐、白胡椒粉和一个鸡蛋，用手抓匀，腌制20分钟以上。

💡 提示：腌制时间越长，肉质越入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (504, 'FBllvNtaClPwnbfWr0gQia', 2, '在一个碗中，将番茄酱、醋、白糖和150ml清水混合，搅拌至糖完全溶解，备用。

💡 提示：确保糖完全溶解，避免结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (505, 'FBllvNtaClPwnbfWr0gQia', 3, '准备一个大碗，里面放淀粉。将腌好的里脊肉条一根根裹上淀粉，抖掉多余的淀粉。

💡 提示：裹粉时要均匀，抖掉多余的淀粉，防止炸制时粘连', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (506, 'FBllvNtaClPwnbfWr0gQia', 4, '锅中倒入足够的油，加热至160℃（可以用筷子试油温，周围冒小泡即可）。将裹好淀粉的里脊肉条下锅炸至表面微黄，捞出沥油。

💡 提示：保持中火，避免炸糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (507, 'FBllvNtaClPwnbfWr0gQia', 5, '将油温升高至200℃，再次将炸过的里脊肉条下锅复炸40秒，捞出沥油。

💡 提示：复炸可以使表皮更加酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (508, 'FBllvNtaClPwnbfWr0gQia', 6, '另起一锅，倒入少量底油，将调好的酱汁倒入锅中，煮至冒泡。将炸好的里脊肉条放入锅中，快速翻炒，使每根肉条都裹上酱汁。

💡 提示：翻炒要快，避免肉条变软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (509, 'FBllvNtaClPwnbfWr0gQia', 7, '关火，将裹好酱汁的里脊肉条盛出，装盘即可。

💡 提示：趁热食用，口感更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (510, 'bsVFYRCJYub6r2n9JVBVpQ', 1, '在一个大碗中加入猪肉末、料酒、生抽、白胡椒粉和一个鸡蛋，搅拌均匀至肉末上劲。

💡 提示：搅拌时要顺着一个方向搅打，使肉末更加紧实。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (511, 'bsVFYRCJYub6r2n9JVBVpQ', 2, '将调好味的猪肉末铺在盘子里，用勺子在肉末中间挖一个小洞。

💡 提示：小洞不要太深，以免蒸制时蛋液溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (512, 'bsVFYRCJYub6r2n9JVBVpQ', 3, '将另一个鸡蛋打入肉末中间的小洞中。

💡 提示：轻轻打入鸡蛋，避免破坏蛋黄。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (513, 'bsVFYRCJYub6r2n9JVBVpQ', 4, '锅中加水至1/4高度，大火烧开后，将装有肉饼的盘子放入锅中，盖上锅盖，转中火蒸15分钟。

💡 提示：水沸后再放入盘子，这样可以保证肉饼受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (514, 'bsVFYRCJYub6r2n9JVBVpQ', 5, '蒸好后，小心取出盘子（注意盘子很烫），撒上适量葱花或香菜即可上桌。

💡 提示：可以用夹子或厚布垫手取盘，防止烫伤。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (515, 'fanMyjhoUO8LZkRFzS9K8n', 1, '将带皮五花肉切成2.5cm见方的小块。

💡 提示：切块时尽量保持大小一致，以便均匀烹饪', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (516, 'fanMyjhoUO8LZkRFzS9K8n', 2, '锅中加入足够的冷水，放入料酒和姜片，再放入五花肉块，开大火煮沸后捞出，用温水冲洗干净并沥干水分。

💡 提示：焯水可以去除肉中的血水和杂质，使肉质更紧实', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (517, 'fanMyjhoUO8LZkRFzS9K8n', 3, '将红腐乳块和腐乳汁碾成泥，加入冰糖、老抽调成酱汁备用。

💡 提示：腐乳自带咸鲜，无需额外加盐', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (518, 'fanMyjhoUO8LZkRFzS9K8n', 4, '热锅冷油，下葱白段和姜片爆香，再下五花肉块煸炒至表面金黄。

💡 提示：煸炒可以使肉块表面形成一层焦香的外壳，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (519, 'fanMyjhoUO8LZkRFzS9K8n', 5, '倒入调好的腐乳酱汁，翻炒均匀，然后加入500ml热水，大火烧开后转小火加盖焖煮40分钟。

💡 提示：小火慢炖可以使肉质更加酥软，汤汁更加浓郁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (520, 'fanMyjhoUO8LZkRFzS9K8n', 6, '40分钟后，开大火收汁，不断晃动锅体避免粘底，直到汤汁变得浓稠且冒鱼眼泡时关火。

💡 提示：收汁时要不断观察，防止糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (521, 'fanMyjhoUO8LZkRFzS9K8n', 7, '将腐乳肉盛出，撒上葱花即可上桌。

💡 提示：葱花可以增加菜品的香气和色彩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (522, '85g5oUxPq2CWXmDETiuOnA', 1, '将白萝卜去皮，滚刀切成3-5cm的大块，备用。

💡 提示：切块大小均匀，便于炖煮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (523, '85g5oUxPq2CWXmDETiuOnA', 2, '将羊排冷水下锅，加入一半的料酒和一半的葱姜，大火煮沸后撇去浮沫，继续煮10分钟。

💡 提示：焯水可以去除羊肉的血水和杂质，使汤更清澈', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (524, '85g5oUxPq2CWXmDETiuOnA', 3, '另起一锅冷水，放入切好的白萝卜，加入一半的冰糖，大火煮沸后转中小火煮5分钟，捞出备用。

💡 提示：焯水可以去除白萝卜的辣味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (525, '85g5oUxPq2CWXmDETiuOnA', 4, '将焯好的羊排放入高压锅中，加水没过所有食材后再增加大约300ml的水。

💡 提示：确保水量充足，避免干烧', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (526, '85g5oUxPq2CWXmDETiuOnA', 5, '将剩余的葱姜、料酒、花椒、冰糖、白芷（可选）、盐放入高压锅中，盖上锅盖，大火加热至上汽后转中小火炖15分钟。

💡 提示：上汽后计时15分钟，确保羊肉熟透', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (527, '85g5oUxPq2CWXmDETiuOnA', 6, '关火，等待高压锅自然放气完毕，开盖，加入之前焯好的萝卜，尝味后加入适量的食盐调味。

💡 提示：根据个人口味调整盐量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (528, '85g5oUxPq2CWXmDETiuOnA', 7, '再次开火，大火加热至上汽后转中小火再炖10分钟。

💡 提示：确保萝卜炖至软烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (529, '85g5oUxPq2CWXmDETiuOnA', 8, '关火，盛盘即可。

💡 提示：小心烫手，慢慢盛出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 1, '蒜苔切成5cm小段，备用', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 2, '五花肉切成5mm×5cm丝状，备用', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 3, '蒜瓣拍碎后切末，备用', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 4, '热锅，倒入10ml食用油，加热10秒至油温升高', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 5, '放入蒜末，中火翻炒出香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 6, '放入五花肉丝和5ml生抽，中火翻炒至肉熟并上色', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('RqVyZMacYxZcqYCXp7pQup', 7, '加入蒜苔段和10ml生抽，翻炒均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (537, 'RqVyZMacYxZcqYCXp7pQup', 8, '加入20ml水，中火翻炒

💡 提示：使蒜苔变软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (538, 'RqVyZMacYxZcqYCXp7pQup', 9, '加入2g食盐，中火翻炒均匀

💡 提示：出锅前可尝味调整咸淡', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (539, '8jSATAz4DCtQoFakselkqy', 1, '将猪肘解冻后用水泡1小时去除血水。

💡 提示：泡水可以有效去除血水和杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (540, '8jSATAz4DCtQoFakselkqy', 2, '使用火焰喷枪灼烧猪肘皮表面至棕黑色以去除猪毛，破坏汗腺。注意不要长时间炙烤同一个位置以避免烧焦，当猪肘皮几乎完全呈现棕黑色时则停止灼烧。如无火焰喷枪，将铁锅烧至200℃以上，将猪肘直接放入锅内，用锅铲或筷子使猪肘皮充分接触铁锅表面，当猪肘皮与铁锅接触位置呈现出棕色时，更换位置继续烫猪肘皮，直到整个猪肘被充分烫过。注意再次过程中注意铁锅温度，不要使铁锅红热。

💡 提示：使用火焰喷枪更方便快捷，但要注意安全', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (541, '8jSATAz4DCtQoFakselkqy', 3, '使用清洁球在水中刷洗猪肘，将其表面烧焦的部分去除。刷洗结束后，猪肘再次呈现出未被灼烧前的状态。

💡 提示：彻底清洗干净，以免影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (542, '8jSATAz4DCtQoFakselkqy', 4, '将猪肘置于铁锅中，加尽量多的冷水，具体视铁锅深度与猪肘大小而定，在保证可以拿得动铁锅及其内容物的情况下，能浸没猪肘3/4以上为最佳。

💡 提示：冷水下锅有助于去除血水和杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (543, '8jSATAz4DCtQoFakselkqy', 5, '取1棵葱的葱白，分成3段，放入锅中。取3粒蒜，分别用刀身拍扁，放入锅中。取3克姜，放入锅中。将2汤匙料酒加入锅中。锅中水烧开后，等待五分钟，随后将猪肘取出，捡出锅中所有配料，更换容器保留所有肉汤备用。

💡 提示：去腥的关键步骤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (544, '8jSATAz4DCtQoFakselkqy', 6, '向锅中加入冷油，以之前水量为参考，能浸没猪肘3/5以上为佳，开中火加热。当油温达到150℃（五成油温）时，转为小火，放入猪肘油炸。在油炸过程中烹饪者应注意人身安全。在油炸过程中，使用锅铲或其他耐高温厨具将锅中的油均匀淋到猪肘未被浸没的部分，如果条件允许应以3分钟的间隔翻转猪肘，使其油炸均匀。油炸过程持续大约20分钟，当观察到猪肘皮已经全部呈现出浅棕色，而瘦肉部分已经微焦，则可捞出备用。

💡 提示：油炸时注意控制油温和时间，防止外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (545, '8jSATAz4DCtQoFakselkqy', 7, '炒糖色：取一小锅，加入30g冰糖和少量水，小火慢慢熬制至冰糖融化并呈深红色，加入200ml热水稀释，备用。

💡 提示：炒糖色时要不断搅拌，防止糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (546, '8jSATAz4DCtQoFakselkqy', 8, '将猪肘加入高压锅内，加入所有肉汤、糖色、香叶、肉桂皮、豆蔻、花椒、大料、老抽、生抽、白醋。如果喜欢甜口，可以再额外加入2-3克冰糖。取1棵葱的葱白，分成3段，放入锅中。取3粒蒜，分别用刀身拍扁，放入锅中。取3克姜，放入锅中。盖上锅盖，加压炖煮40分钟（压力等级为中压）。

💡 提示：高压锅炖煮可以使肉质更加酥烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (547, '8jSATAz4DCtQoFakselkqy', 9, '在炖煮期间调制水淀粉。取碗1个，加入1汤匙淀粉，100ml水，搅拌使其成为白色悬浊液。

💡 提示：水淀粉要提前准备好，以便随时使用', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (548, '8jSATAz4DCtQoFakselkqy', 10, '炖煮时间结束后，打开高压锅锅盖，捡出锅中所有的配料，只保留猪肘。将高压锅中剩余的肉汤转移至铁锅内，猪肘转移至盘子或盆内。将铁锅置于灶台上，开大火。在收汁过程中可以用筷子头蘸取锅内汤汁判断咸淡，并根据口味添加盐。注意，汤汁多的时候味道会比汤汁少的时候味道更淡，加入盐时需要考虑这一点。当肉汤沸腾时，注意观察剩余肉汤余量。当剩余肉汤少于原肉汤体积的1/2时，再次搅拌之前调制好的水淀粉，并加入一半。等待肉汤沸腾，加入剩下的一半。等待肉汤沸腾，沸腾后等待1-2分钟关火，此时锅内的肉汤呈红棕色粘稠状。用汤匙舀起肉汤均匀地淋在猪肘上，尽量使猪肘的每一处都淋到汤汁。如果在猪肘被完全淋到前汤汁已经用完则可直接上桌，否则剩余汤汁不需要再淋，可直接上桌。

💡 提示：收汁时要不断搅拌，防止糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (549, '9Ad5xcTwEOcFw8DvOTVVTQ', 1, '将红薯粉丝用冷水浸泡20分钟至完全泡软，捞出沥干水分备用。

💡 提示：粉丝不宜久泡或煮太久，否则易断、口感变差。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 2, '蒜、姜分别剁成末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (551, '9Ad5xcTwEOcFw8DvOTVVTQ', 3, '锅烧热，倒入食用油，放入蒜末、姜末，中小火炒香至散发香味。

💡 提示：避免大火炒糊姜蒜。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 4, '加入猪肉末，中火翻炒至肉色发白、微微出油。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (553, '9Ad5xcTwEOcFw8DvOTVVTQ', 5, '加入郫县豆瓣酱，继续中火炒至红油析出。

💡 提示：确保豆瓣酱充分炒香以去生味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 6, '加入生抽、老抽，翻炒均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 7, '倒入清水，大火烧沸。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('9Ad5xcTwEOcFw8DvOTVVTQ', 8, '放入泡软沥干的粉丝，用筷子轻轻拨散防止粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (557, '9Ad5xcTwEOcFw8DvOTVVTQ', 9, '转中小火，加盖或不盖（依火力调节），煮约5分钟，至粉丝完全吸收汤汁、呈微微收干状态。

💡 提示：全程注意翻动防糊底；若汤汁过多可开盖稍收汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (558, '9Ad5xcTwEOcFw8DvOTVVTQ', 10, '关火，依口味撒入小葱末（可选），装盘。

💡 提示：白胡椒粉0.5g可在此步或步骤6中加入，风味更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 1, '将排骨用冷水浸泡10分钟，换水重复2次以泡去血水，再用厨房纸彻底吸干表面水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (560, 'nvV7dQtRqUIbXC1uoCXhTU', 2, '将阳江豆豉放入30 ml清水中浸泡5分钟，捞出后稍剁碎

💡 提示：豆豉浸泡后剁碎更易释放豉香，提升入味效果', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (561, 'nvV7dQtRqUIbXC1uoCXhTU', 3, '将处理好的排骨、泡剁碎的豆豉、蒜蓉、姜末、生抽、老抽、蚝油、白砂糖、生粉、10 ml食用油和适量清水（如需调节湿度）混合均匀，腌制8–30分钟

💡 提示：腌制时间越长越入味，建议至少15分钟', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (562, 'nvV7dQtRqUIbXC1uoCXhTU', 4, '蒸锅加水烧开，将腌好的排骨平铺于盘中，水开后上锅大火蒸18分钟

💡 提示：蒸制时间需根据排骨块大小调整，以筷子能轻松插入软骨处为准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('nvV7dQtRqUIbXC1uoCXhTU', 5, '关火后焖2分钟', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (564, 'nvV7dQtRqUIbXC1uoCXhTU', 6, '另起小锅，倒入剩余10 ml食用油，加热至180–200 ℃（油面微有青烟、轻微波动）

💡 提示：油温不足则香气不扬，过高易焦苦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (565, 'nvV7dQtRqUIbXC1uoCXhTU', 7, '将蒸好的排骨取出，均匀撒上葱花和白芝麻，立即淋入热油激香

💡 提示：传统做法不加此步；淋油前确保排骨表面无过多积水，以免溅油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (566, 'WcpVcmbH7YbWiq5PPyjfOv', 1, '将青椒洗净，去蒂和籽，用滚刀法切段备用。

💡 提示：滚刀法指斜刀切并滚动食材，使切面呈菱形，利于受热均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 2, '大蒜拍松后横切成蒜瓣；生姜切碎成姜末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (568, 'WcpVcmbH7YbWiq5PPyjfOv', 3, '猪瘦肉顺着纹理（刀与肌纤维平行）切成薄片，洗净后放入碗中。

💡 提示：顺纹切可保持肉片嫩滑，纹路呈‘川’字形', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 4, '在肉片中加入生抽3ml、蚝油3ml、盐1g，搅拌均匀，腌制10分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (570, 'WcpVcmbH7YbWiq5PPyjfOv', 5, '热锅（不放油），放入青椒段，大火干煸至表面起皱、呈虎皮状。

💡 提示：虎皮状指表皮微焦、泛黄褐斑，香气释放明显', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (571, 'WcpVcmbH7YbWiq5PPyjfOv', 6, '向干煸好的青椒中加入2g盐，继续翻炒1分钟，盛出备用。

💡 提示：无需洗锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (572, 'WcpVcmbH7YbWiq5PPyjfOv', 7, '同一锅大火烧热，倒入8ml油，待油温升高（约30秒），下蒜瓣和姜末爆香。

💡 提示：油温以轻微冒烟或波动明显为宜', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (573, 'WcpVcmbH7YbWiq5PPyjfOv', 8, '倒入腌好的肉片，大火快速翻炒至变色、断生。

💡 提示：避免久炒以防肉质变柴', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 9, '加入干煸青椒，翻炒均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('WcpVcmbH7YbWiq5PPyjfOv', 10, '按口味加入豆豉3g，最后淋入酱油2ml，翻炒30秒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (576, '3KeACat4a0Ycb4FvnuybNG', 1, '将猪里脊切成细丝，加入3ml生抽和5g淀粉，搅拌均匀腌制10分钟。

💡 提示：腌制可以使肉丝更加嫩滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (577, '3KeACat4a0Ycb4FvnuybNG', 2, '青椒洗净后用滚刀手法切丝备用。

💡 提示：滚刀切法可以使青椒更易熟且美观', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (578, '3KeACat4a0Ycb4FvnuybNG', 3, '大蒜横切成片，香干切成细丝。

💡 提示：切好的香干丝可以稍微用水冲洗一下，去除豆腥味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (579, '3KeACat4a0Ycb4FvnuybNG', 4, '取一个小碗，将剩余的5g淀粉与10ml水混合，搅拌均匀备用。

💡 提示：勾芡前要确保淀粉完全溶解在水中', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (580, '3KeACat4a0Ycb4FvnuybNG', 5, '热锅冷油，倒入30ml食用油，不用等油热就倒入腌制好的肉丝，用中小火慢慢划散，待肉丝变色后捞出备用。

💡 提示：肉丝不要炒得太久，以免变老', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (581, '3KeACat4a0Ycb4FvnuybNG', 6, '锅中留底油，放入蒜片和香干丝，加入2ml生抽，翻炒均匀。

💡 提示：保持中小火，防止蒜片炒糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (582, '3KeACat4a0Ycb4FvnuybNG', 7, '加入青椒丝，继续翻炒2-3分钟。

💡 提示：青椒丝不宜炒太久，以保持脆嫩口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (583, '3KeACat4a0Ycb4FvnuybNG', 8, '将炒好的肉丝重新倒入锅中，加入剩余的生抽、盐和鸡精，快速翻炒均匀。

💡 提示：调味料要均匀撒在食材上', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (584, '3KeACat4a0Ycb4FvnuybNG', 9, '最后倒入事先调好的淀粉水勾芡，翻炒2-3分钟至汤汁浓稠即可出锅。

💡 提示：勾芡时要边倒边快速翻炒，防止结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (585, 'qVJANVrCZxopxQg6vgBb8j', 1, '准备腌料：将生抽5ml、料酒5ml、淀粉5g、水20ml、蛋清1个混合均匀。

💡 提示：确保淀粉完全溶解，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (586, 'qVJANVrCZxopxQg6vgBb8j', 2, '准备香汁：将生抽5ml、醋15ml、白糖10g、盐1g、淀粉5g、水20ml混合均匀。

💡 提示：建议提前调匀，防止下锅后沉淀或糊锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (587, 'qVJANVrCZxopxQg6vgBb8j', 3, '处理里脊肉：切丝，用腌料抓匀，腌制15–30分钟。

💡 提示：沿肉纹切丝更嫩，抓匀至表面起黏液为佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (588, 'qVJANVrCZxopxQg6vgBb8j', 4, '泡发木耳：干木耳5g用冷水浸泡4小时，洗净后切小块。

💡 提示：勿用热水急泡，易软烂失脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (589, 'qVJANVrCZxopxQg6vgBb8j', 5, '处理蔬菜：青椒去蒂切丝；胡萝卜洗净切丝；姜、蒜切末；葱切5mm段。

💡 提示：胡萝卜丝建议沸水焯烫30秒至断生，捞出过凉水保持脆感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (590, 'qVJANVrCZxopxQg6vgBb8j', 6, '滑炒肉丝：热锅加15ml油，倒入腌好的肉丝，快速滑散至变白（约1分钟），盛出备用。

💡 提示：油温六成热（约150℃），避免肉丝粘连或过老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (591, 'qVJANVrCZxopxQg6vgBb8j', 7, '爆香调料：锅烧热，加5ml油，下葱末、姜末、蒜末、豆瓣酱，中小火炒出红油和香味（约30秒）。

💡 提示：豆瓣酱需煸透去生味，但不可焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (592, 'qVJANVrCZxopxQg6vgBb8j', 8, '炒配菜：倒入胡萝卜丝，翻炒20秒；再加入青椒丝和木耳，继续翻炒2分钟至断生。

💡 提示：全程中大火快炒，保持蔬菜爽脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (593, 'qVJANVrCZxopxQg6vgBb8j', 9, '合炒：倒入滑熟的肉丝，快速翻炒均匀（不超过20秒）。

💡 提示：避免肉丝变柴，动作要快。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (594, 'qVJANVrCZxopxQg6vgBb8j', 10, '淋汁收锅：倒入调好的香汁，急速翻炒至汤汁浓稠、均匀裹附食材（不超过15秒），立即关火。

💡 提示：锅气足时淋汁，高温激发出鱼香味，切忌久炒导致酸味挥发或糖焦化。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (595, 'Z4DnrchAd17fcyOePFCpbf', 1, '烧开一锅水（水量能没过第 2-4 步中的食材即可）。

💡 提示：确保水完全沸腾后再放入食材', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (596, 'Z4DnrchAd17fcyOePFCpbf', 2, '在开水中放入青菜，焯 1 分钟后盛出备用。

💡 提示：青菜焯水时间不宜过长，以免营养流失和软烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (597, 'Z4DnrchAd17fcyOePFCpbf', 3, '在开水中放入无骨肉，焯 2 分钟后盛出备用。

💡 提示：肉质变色即可捞出，避免煮老', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (598, 'Z4DnrchAd17fcyOePFCpbf', 4, '在开水中放入北京麻辣方便面，煮 2 分钟后盛出备用。

💡 提示：面条煮至八成熟即可', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (599, 'Z4DnrchAd17fcyOePFCpbf', 5, '倒出开水，擦干锅具，放入 105 克食用油，大火加热 30 秒。

💡 提示：油温要高，以便快速炒香调料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (600, 'Z4DnrchAd17fcyOePFCpbf', 6, '放入麻辣香锅调料，翻炒 20 秒。

💡 提示：快速翻炒使调料均匀受热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (601, 'Z4DnrchAd17fcyOePFCpbf', 7, '放入干辣椒，翻炒 10 秒。

💡 提示：干辣椒容易糊，注意火候', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (602, 'Z4DnrchAd17fcyOePFCpbf', 8, '放入焯过的青菜，改中火，翻炒 3 分钟。

💡 提示：保持中火，防止青菜炒焦', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (603, 'Z4DnrchAd17fcyOePFCpbf', 9, '放入焯过的无骨肉，翻炒 3 分钟。

💡 提示：肉质要炒至表面微焦，更加入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (604, 'Z4DnrchAd17fcyOePFCpbf', 10, '放入煮过的北京麻辣方便面，用筷子翻动 1 分钟。

💡 提示：面条要均匀裹上调料，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (605, 'Z4DnrchAd17fcyOePFCpbf', 11, '关火，出锅。

💡 提示：趁热享用，味道更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (606, 'lAq7KME8YL9vHyeRdinh7x', 1, '将鸡腿洗净，剁成4cm大小的块。

💡 提示：鸡肉块不要太大，以便更好地入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (607, 'lAq7KME8YL9vHyeRdinh7x', 2, '生姜切片，干辣椒切成小圈。

💡 提示：生姜和干辣椒可以增加菜肴的香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (608, 'lAq7KME8YL9vHyeRdinh7x', 3, '香菇切片，青椒切成细长的马蹄状。若使用干香菇，需提前泡发并保留香菇水。

💡 提示：香菇水可以增加汤汁的鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (609, 'lAq7KME8YL9vHyeRdinh7x', 4, '若有土豆，切成与鸡肉大小类似的滚刀块。

💡 提示：土豆可以使汤汁更粘稠，口感更丰富。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (610, 'lAq7KME8YL9vHyeRdinh7x', 5, '炒糖色：锅里倒入底油，冷油时放入白糖，小火慢慢加热，待油温逐渐升高，白糖开始融化并变成较深的棕色（期间要不断搅拌，防止糊锅）。迅速倒入鸡块，转大火，快速翻炒！烹入料酒，继续翻炒片刻。

💡 提示：炒糖色是关键步骤，新手可以选择跳过这一步，直接用老抽替代。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (611, 'lAq7KME8YL9vHyeRdinh7x', 6, '将生姜片和干辣椒倒入锅中，翻炒均匀。

💡 提示：生姜和干辣椒能去腥增香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (612, 'lAq7KME8YL9vHyeRdinh7x', 7, '放入酱油，炒匀。

💡 提示：酱油可以增加菜肴的颜色和味道。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (613, 'lAq7KME8YL9vHyeRdinh7x', 8, '倒入香菇水或清水，以能淹住鸡肉为准。放入香菇片、白胡椒粉、盐和土豆。

💡 提示：香菇水可以使汤汁更加鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (614, 'lAq7KME8YL9vHyeRdinh7x', 9, '翻炒均匀后，盖上锅盖焖煮，转中小火15-20分钟，有条件可以转至砂锅。

💡 提示：焖煮过程中注意观察汤汁，避免烧干。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (615, 'lAq7KME8YL9vHyeRdinh7x', 10, '待鸡肉软烂，汤汁浓稠后（汤汁不要收得太干），最后放入青椒。

💡 提示：青椒不宜久煮，以免失去脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (616, 'lAq7KME8YL9vHyeRdinh7x', 11, '放入味精，兜炒均匀后，关火！青椒基本断生即可，不要炒时间久了。

💡 提示：味精可根据个人口味添加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (617, 'Z9l0TcOPma9S43Vrzjud5N', 1, '将猪瘦肉切成薄片，放入碗中，加入10克食用油和1汤匙生抽，搅拌均匀，腌制10分钟。

💡 提示：腌制可以使肉质更加嫩滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (618, 'Z9l0TcOPma9S43Vrzjud5N', 2, '将黄瓜切去头尾，斜着切成0.5厘米厚的薄片，放入碗中，撒上8克盐，搅拌均匀，腌制5分钟。

💡 提示：腌制黄瓜可以去除部分水分，使口感更脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (619, 'Z9l0TcOPma9S43Vrzjud5N', 3, '将腌制好的黄瓜挤干水分备用。

💡 提示：挤干水分可以避免炒制时出水过多', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (620, 'Z9l0TcOPma9S43Vrzjud5N', 4, '将蒜瓣去皮，压扁，切成蒜末；小米辣去蒂，切成0.5厘米长的段状。

💡 提示：蒜末和小米辣要切得细碎，便于炒香', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (621, 'Z9l0TcOPma9S43Vrzjud5N', 5, '热锅，倒入40克食用油，待油温升至七成热（约180℃），放入蒜末和小米辣，快速翻炒几下，炒出香味。

💡 提示：油温不宜过高，以免蒜末和小米辣炒糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (622, 'Z9l0TcOPma9S43Vrzjud5N', 6, '放入腌制好的猪瘦肉，大火快速翻炒至肉变色。

💡 提示：大火快炒可以使肉质更加嫩滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (623, 'Z9l0TcOPma9S43Vrzjud5N', 7, '放入挤干水分的黄瓜片，加入2克盐，大火快速翻炒均匀，炒至黄瓜断生即可出锅。

💡 提示：大火快炒可以保持黄瓜的脆嫩口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (624, 'WHtomsdZmNYj1YPezqSZSZ', 1, '准备一锅水，加入500ml水，大火煮沸。

💡 提示：确保水完全沸腾后再放入绿豆芽', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (625, 'WHtomsdZmNYj1YPezqSZSZ', 2, '将绿豆芽放入锅中，大火煮60秒。捞出后过凉水，沥干水分，放入盘中备用。

💡 提示：过凉水可以使豆芽更加脆嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (626, 'WHtomsdZmNYj1YPezqSZSZ', 3, '黄瓜洗净后切成细丝，放入盘中备用。

💡 提示：黄瓜丝要切得均匀，这样口感更好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (627, 'WHtomsdZmNYj1YPezqSZSZ', 4, '将10g蒜瓣剥皮，放入蒜臼中加入1g盐，锤成蒜泥，加入10g自来水，搅拌均匀，放置备用。

💡 提示：蒜泥加水可以使其更易拌匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (628, 'WHtomsdZmNYj1YPezqSZSZ', 5, '准备一个小碗，加入3g盐、2g鸡精、5g生抽、1g老抽、1g香油、2g蚝油、5g香醋，再加入25-35g温水，用筷子将其拌匀、溶解。静置一旁冷却。

💡 提示：调料的比例可以根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (629, 'WHtomsdZmNYj1YPezqSZSZ', 6, '准备另一个小碗，将60g芝麻酱放入其中，加入4g盐、3g鸡精、5g生抽、1g老抽、3g蚝油，用筷子将其调料与芝麻酱拌匀。然后分次加入10g清水，每次加入后都要充分搅拌，直至达到理想的浓稠度。

💡 提示：芝麻酱的浓稠度可以根据个人喜好调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (630, 'WHtomsdZmNYj1YPezqSZSZ', 7, '将凉皮放入盆中，倒入调好的盐水，用筷子将其拌匀。随后盛入小碗中（盐水一并倒入碗中）。

💡 提示：确保凉皮和调料充分混合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (631, 'WHtomsdZmNYj1YPezqSZSZ', 8, '在凉皮上依次放上绿豆芽、面筋。

💡 提示：摆放整齐，美观大方', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (632, 'WHtomsdZmNYj1YPezqSZSZ', 9, '将调配好的芝麻酱从面筋上方倒下。

💡 提示：芝麻酱可以稍微多一些，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (633, 'WHtomsdZmNYj1YPezqSZSZ', 10, '撒上黄瓜丝。

💡 提示：黄瓜丝可以增加清爽感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (634, 'WHtomsdZmNYj1YPezqSZSZ', 11, '如有喜爱可以加入辣椒油。

💡 提示：辣椒油可以增加辣味，根据个人口味添加', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (635, 'Tnnr5cwpw2jMpY0sjpFAS1', 1, '将平底锅预热至中火。

💡 提示：确保锅底均匀受热，避免粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (636, 'Tnnr5cwpw2jMpY0sjpFAS1', 2, '将50ml清水倒入平底锅中。

💡 提示：水不要太多，以免影响面条口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (637, 'Tnnr5cwpw2jMpY0sjpFAS1', 3, '将半成品意大利面放入平底锅中，用铲子轻轻翻炒1分钟。

💡 提示：保持中火，让面条均匀受热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (638, 'Tnnr5cwpw2jMpY0sjpFAS1', 4, '将附带的酱料倒入锅中，继续翻炒1分钟，使面条和酱料充分混合。

💡 提示：根据个人口味调整酱料用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (639, 'Tnnr5cwpw2jMpY0sjpFAS1', 5, '将炒好的意大利面装盘，即可享用。

💡 提示：可以撒上一些芝士粉或香草增加风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (640, 'rq2x1iHxVweAsAPBMULQXZ', 1, '将牛油放入锅中，用大火加热至八成热（约240±10°C），加入老姜、大葱、洋葱、大蒜各100g，炸至金黄后捞出扔掉。

💡 提示：炸制过程中要不断搅拌，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (641, 'rq2x1iHxVweAsAPBMULQXZ', 2, '加入色拉油或菜籽油、纯猪油，待油温降至五成热（约150±10°C）时，加入糍粑辣椒，持续翻炒5-8分钟。

💡 提示：糍粑辣椒要提前泡软，这样更容易炒出香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (642, 'rq2x1iHxVweAsAPBMULQXZ', 3, '加入豆瓣酱，炒散，转中小火慢炒至料渣略发白翻砂（发出沙沙声）。

💡 提示：中小火慢炒可以使豆瓣酱充分释放香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (643, 'rq2x1iHxVweAsAPBMULQXZ', 4, '当油呈现樱桃红色时，加入剩余的老姜片（150g）、大蒜（100g），炒香约15秒。

💡 提示：快速翻炒，避免焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (644, 'rq2x1iHxVweAsAPBMULQXZ', 5, '加入豆鼓、豆母子，炒香，再加入红花椒、小茴香炒香。

💡 提示：豆鼓和豆母子要提前剁碎，以便更好地融入底料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (645, 'rq2x1iHxVweAsAPBMULQXZ', 6, '加入颗粒香料，炒散，再加入麦芽粉炒散，最后加入白酒炒散。

💡 提示：颗粒香料要提前打碎至约4mm大小，便于炒制。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (646, 'rq2x1iHxVweAsAPBMULQXZ', 7, '将整形香料洗净后，放入锅中，继续翻炒均匀。

💡 提示：整形香料要保持完整，不要打碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (647, 'rq2x1iHxVweAsAPBMULQXZ', 8, '起锅装入容器中，静置于温度低的环境（10-20℃）5天后再使用效果最佳。

💡 提示：低温保存可以更好地融合各种香料的味道。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (648, 'ao6tyOztRSEA85STsIxTrM', 1, '将适量的水倒入锅中，水量约为饺子高度的1-2倍。

💡 提示：确保水足够多，避免饺子粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (649, 'ao6tyOztRSEA85STsIxTrM', 2, '开中火，等待水煮沸。

💡 提示：水沸腾后再下饺子，这样饺子不容易粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (650, 'ao6tyOztRSEA85STsIxTrM', 3, '将速冻水饺倒入锅中。

💡 提示：可以先用水稍微冲洗一下饺子，防止粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (651, 'ao6tyOztRSEA85STsIxTrM', 4, '用炒菜勺子或铲子轻轻搅动水，但不要碰到饺子，以免撕破皮。

💡 提示：搅动可以帮助饺子均匀受热，防止粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (652, 'ao6tyOztRSEA85STsIxTrM', 5, '当饺子浮起且水再次煮沸后，用炒菜勺子盛起一个饺子观察是否熟透。

💡 提示：如果面皮有夹生，可以加入80ml凉水降温，继续煮至沸腾。最多加两次水即可全熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (653, 'ao6tyOztRSEA85STsIxTrM', 6, '所有饺子浮起后（约8-10分钟），用漏勺将饺子捞出装盘。

💡 提示：确保饺子完全煮熟，外皮透明且馅料熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (654, 'OacdhYNMJMI53ynRvCsh9Z', 1, '将600ml水倒入电饭煲中，按下煮或炖模式，等待水沸腾（约5-10分钟）。

💡 提示：确保水完全沸腾后再下馄饨，这样可以避免粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (655, 'OacdhYNMJMI53ynRvCsh9Z', 2, '将速冻馄饨小心放入沸水中，注意不要烫伤。如果馄饨有调料包，此时可一并加入水中。

💡 提示：轻轻搅拌一下，防止馄饨粘在一起。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (656, 'OacdhYNMJMI53ynRvCsh9Z', 3, '盖上电饭煲，继续按煮或炖模式运行15-20分钟。

💡 提示：中途可以打开盖子检查一次，确保馄饨没有粘底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (657, 'OacdhYNMJMI53ynRvCsh9Z', 4, '将所有馄饨连同能没过所有馄饨的水一同盛入碗中。

💡 提示：可以用漏网捞出馄饨，再加入适量的汤水。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (658, 'OacdhYNMJMI53ynRvCsh9Z', 5, '如果此前没有加入调料包，此时可按自身口味轻重加入盐、鸡精、胡椒粉、香油调味。撒上5-8片香菜叶佐味（仅适用于对香菜味道不敏感的人）。

💡 提示：调味时可以尝一下汤的味道，根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (659, 'QEIR2M4Yx9STlMS7BJ9cSI', 1, '白蘑菇切片，洋葱切末，备用。

💡 提示：可预留少量蘑菇片煎香后作装饰', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (660, 'QEIR2M4Yx9STlMS7BJ9cSI', 2, '平底锅中放入黄油，小火加热约1–2分钟至完全融化。

💡 提示：避免大火以防黄油焦化', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (661, 'QEIR2M4Yx9STlMS7BJ9cSI', 3, '加入洋葱末，小火炒约3–4分钟至变软、透明。

💡 提示：保持搅拌防粘底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (662, 'QEIR2M4Yx9STlMS7BJ9cSI', 4, '加入白蘑菇片，中火翻炒约5分钟至出水、变软。

💡 提示：待水分基本蒸发、蘑菇边缘微焦更香', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (663, 'QEIR2M4Yx9STlMS7BJ9cSI', 5, '撒入面粉，快速翻炒1分钟至与食材均匀裹合、无干粉。

💡 提示：防止结块，确保面粉熟化去生味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (664, 'QEIR2M4Yx9STlMS7BJ9cSI', 6, '缓慢倒入牛奶和清水（或鸡高汤），边倒边搅拌至均匀无颗粒。

💡 提示：建议牛奶分次加入，更易乳化', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (665, 'QEIR2M4Yx9STlMS7BJ9cSI', 7, '转中小火加热至微沸（非剧烈沸腾），持续搅拌防糊底。

💡 提示：‘微沸’指边缘冒小泡，避免大火沸腾导致分离', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (666, 'QEIR2M4Yx9STlMS7BJ9cSI', 8, '调至小火，保持微沸状态煮约10分钟，期间不时搅拌，至汤汁明显浓稠。

💡 提示：浓稠度以勺背挂薄层、滴落缓慢为准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (667, 'QEIR2M4Yx9STlMS7BJ9cSI', 9, '倒入淡奶油，继续小火加热1分钟，不停搅拌。

💡 提示：勿煮沸，以免奶油油水分离', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (668, 'QEIR2M4Yx9STlMS7BJ9cSI', 10, '关火，加入盐和黑胡椒碎调味，搅拌均匀。

💡 提示：建议先尝味再调整咸淡', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (669, 'QEIR2M4Yx9STlMS7BJ9cSI', 11, '如需细腻口感，将汤稍冷却后用料理机打成顺滑浓汤（可选）。

💡 提示：热汤请勿满杯高速搅打，注意安全放气', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (670, 'gyEity9YJbs5usYWkOClhG', 1, '将100克小米放入碗中，用水轻淘一遍，用手轻轻搅拌一下，然后倒掉水，去除浮灰。

💡 提示：不要搓洗小米，以免损失小米油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (671, 'gyEity9YJbs5usYWkOClhG', 2, '在锅中加入2000克水，大火烧开。

💡 提示：务必确保水完全沸腾', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (672, 'gyEity9YJbs5usYWkOClhG', 3, '水烧开后，将淘好的小米倒入锅中。

💡 提示：小米要在水开的时候下锅，这是关键步骤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (673, 'gyEity9YJbs5usYWkOClhG', 4, '用勺子搅拌几下，使小米均匀分散，防止粘连锅底。继续用大火熬煮6-8分钟，期间每隔2分钟搅拌一次。

💡 提示：保持大火，但要频繁搅拌以防糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (674, 'gyEity9YJbs5usYWkOClhG', 5, '改用中火，继续熬煮15-20分钟，期间每隔5分钟搅拌一次。锅盖要错开一条缝，以防止小米油溜走。

💡 提示：中火慢炖可以使小米更加软糯，同时保留小米的香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (675, 'OLwZMEEK4egV9vXNUM3HG1', 1, '将前腿肉改刀切成小块，肥瘦三七分。用刀背砸一砸，把肉筋打开打松疏，剁成肉末。

💡 提示：手工剁肉比机器打的更松散，口感更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (676, 'OLwZMEEK4egV9vXNUM3HG1', 2, '在肉末中加入18g盐和6g胡椒粉，用手抓匀。

💡 提示：确保调料均匀分布。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (677, 'OLwZMEEK4egV9vXNUM3HG1', 3, '分次加入240ml葱姜花椒水，边加边搅，用手揉匀，让肉吸饱水。

💡 提示：水分要逐渐加入，避免肉馅太稀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (678, 'OLwZMEEK4egV9vXNUM3HG1', 4, '加入1个鸡蛋清，继续顺着一个方向搅匀。

💡 提示：顺一个方向搅拌可以使肉馅更加紧实。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (679, 'OLwZMEEK4egV9vXNUM3HG1', 5, '加入40g土豆淀粉，搅匀。

💡 提示：淀粉可以增加肉丸的弹性和口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (680, 'OLwZMEEK4egV9vXNUM3HG1', 6, '最后加入20ml熟豆油，搅拌均匀。

💡 提示：豆油可以使肉丸更加嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (681, 'OLwZMEEK4egV9vXNUM3HG1', 7, '起锅烧水，烧开后改小火，使水呈似开非开的状态。

💡 提示：小火可以使肉丸慢慢定型，不易散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (682, 'OLwZMEEK4egV9vXNUM3HG1', 8, '手上沾点水，挤出丸子放入锅中，全部漂起来后，用小火煮1分钟。

💡 提示：手沾水可以防止肉馅粘手。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (683, 'OLwZMEEK4egV9vXNUM3HG1', 9, '将泡好的粉丝铺在碗底，加入泡发后的木耳、黄花和小香葱。

💡 提示：提前泡软粉丝，使其更容易入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (684, 'OLwZMEEK4egV9vXNUM3HG1', 10, '将煮好的丸子连同汤一起倒入碗中，加入适量的盐、胡椒粉和鸡粉调味。

💡 提示：根据个人口味调整调味料的用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (685, 'OLwZMEEK4egV9vXNUM3HG1', 11, '淋上3-5滴香油，撒上一小颗香菜即可。

💡 提示：香油和香菜可以提升汤的香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (686, 'oLQDeggmNRnxo5YUylCW42', 1, '将牛肉切成薄片，放入碗中，加入2g盐和0.5g胡椒粉腌制15-20分钟。

💡 提示：腌制可以使牛肉更加入味，口感更嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (687, 'oLQDeggmNRnxo5YUylCW42', 2, '番茄洗净后切成小块；葱切成葱花；姜切成姜片；蒜剁成蒜泥。

💡 提示：番茄切块时尽量保持大小均匀，以便煮熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (688, 'oLQDeggmNRnxo5YUylCW42', 3, '锅中加入1.5L清水，大火烧开。

💡 提示：水要一次性加足，避免中途加水影响汤的口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (689, 'oLQDeggmNRnxo5YUylCW42', 4, '水开后加入姜片和腌好的牛肉片，用筷子轻轻拨散，煮至牛肉变色（约2-3分钟）。

💡 提示：牛肉变色即可，不要煮太久以免变老。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (690, 'oLQDeggmNRnxo5YUylCW42', 5, '加入番茄块，继续煮至番茄变软（约5分钟）。

💡 提示：番茄煮软后会释放出更多的汁液，使汤更加鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (691, 'oLQDeggmNRnxo5YUylCW42', 6, '将打散的鸡蛋液缓慢倒入锅中，同时用筷子轻轻搅拌形成蛋花。

💡 提示：倒鸡蛋液时要慢慢倒入，并不断搅拌，这样蛋花才会细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (692, 'oLQDeggmNRnxo5YUylCW42', 7, '加入剩余的2g盐和0.5g胡椒粉调味，最后撒上葱花，关火即可出锅。

💡 提示：调味时可以尝一下汤的味道，根据个人口味适当调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (693, 'EkrYb2I7w2pNRh1KIiUe9j', 1, '将大米洗净后放入电饭锅内胆中，加入1升饮用水。

💡 提示：提前浸泡大米可以使粥更加绵软。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (694, 'EkrYb2I7w2pNRh1KIiUe9j', 2, '瘦肉洗净后晾去水分，加入10毫升食用油，揉搓均匀，放入电饭锅内胆中。

💡 提示：用油腌制瘦肉可以使其更加嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (695, 'EkrYb2I7w2pNRh1KIiUe9j', 3, '皮蛋去壳后洗净，对半切开，分离蛋白和蛋黄。蛋白切成小块，蛋黄揉碎，放入电饭锅内胆中。

💡 提示：皮蛋切块时尽量保持大小均匀，以便煮熟后口感一致。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (696, 'EkrYb2I7w2pNRh1KIiUe9j', 4, '生姜洗净削皮，去除枯黄部分，切成细丝，放入电饭锅内胆中。

💡 提示：姜丝可以去腥增香。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (697, 'EkrYb2I7w2pNRh1KIiUe9j', 5, '将电饭锅调至煮粥模式，煮约40-50分钟，直至粥变得浓稠。

💡 提示：煮粥过程中可适当搅拌，防止粘底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (698, 'EkrYb2I7w2pNRh1KIiUe9j', 6, '在等待粥煮熟的过程中，处理配料：小葱、香菜、生菜分别洗净，去除根部和枯黄部分，切成碎末，放入小碗备用。

💡 提示：切好的配料可以放在冰箱冷藏，以保持新鲜。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (699, 'EkrYb2I7w2pNRh1KIiUe9j', 7, '准备酱料：将5毫升酱油、5毫升蚝油、2克盐和1克胡椒粉混合均匀，放入小碗备用。

💡 提示：调味料可以根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (700, 'EkrYb2I7w2pNRh1KIiUe9j', 8, '粥煮好后，将生菜放入沸水中焯水约10秒，捞出沥干水分。

💡 提示：焯水时间不宜过长，以免生菜失去脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (701, 'EkrYb2I7w2pNRh1KIiUe9j', 9, '将焯好的生菜、小葱碎、香菜碎以及调好的酱料一起加入电饭锅内，关火后用余温焖拌均匀。

💡 提示：利用余温焖拌可以使配料更好地融入粥中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (702, 'S8wNJtw5726nZk0nDhqRUd', 1, '将150克大米淘洗干净，去除杂质。

💡 提示：淘洗时轻轻搓揉，不要用力过猛，以免破坏米粒', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (703, 'S8wNJtw5726nZk0nDhqRUd', 2, '（可选）将15毫升植物油与洗净的大米混合均匀，尽量确保每粒米上都沾上少量油。

💡 提示：这一步可以使米粥更加香滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (704, 'S8wNJtw5726nZk0nDhqRUd', 3, '将米和1.35升水加入锅中。

💡 提示：使用砂锅或不锈钢锅效果更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (705, 'S8wNJtw5726nZk0nDhqRUd', 4, '开大火，加热至沸腾。

💡 提示：注意观察，防止溢出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (706, 'S8wNJtw5726nZk0nDhqRUd', 5, '在沸腾后，将火关小，保持微沸状态继续煮。

💡 提示：微沸状态下，米粥会慢慢变稠', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (707, 'S8wNJtw5726nZk0nDhqRUd', 6, '煮至米粥浓稠，米粒开花，即可关火。

💡 提示：可以用勺子舀起米粥，如果能挂勺且米粒开花，说明已经煮好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (708, 'KhqppAi6wq0SJXIufN7o7f', 1, '将干紫菜用清水泡15分钟，捞起沥干水分备用。

💡 提示：紫菜泡软后更容易煮熟，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (709, 'KhqppAi6wq0SJXIufN7o7f', 2, '热锅，倒入500ml清水、5ml油和2g盐，待水开后放入紫菜。

💡 提示：加少量油可以使汤更加鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (710, 'KhqppAi6wq0SJXIufN7o7f', 3, '紫菜烧开后继续煮3分钟，然后将打好的蛋液徐徐倒入锅内，边倒边搅拌，形成蛋花。

💡 提示：蛋液要慢慢倒入，同时轻轻搅拌，这样蛋花会更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (711, 'KhqppAi6wq0SJXIufN7o7f', 4, '撒上葱花，转小火煮20秒。

💡 提示：撒葱花后立即转小火，保持汤的温度。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (712, 'KhqppAi6wq0SJXIufN7o7f', 5, '关火，出锅前放入几滴香油，如果喜欢可以加入一点虾皮或虾仁。

💡 提示：香油和虾皮/虾仁能增加汤的香气和口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (713, 'qRV5nI3NaW5OXmTK5p0foI', 1, '将洋葱、胡萝卜、欧芹切成1cm见方的小丁；红肠、马铃薯切成2cm块；包菜去梗后手撕成2cm片；牛肉撒上12g盐和12g黑胡椒腌制5分钟。

💡 提示：切配时尽量保持大小一致，以便均匀烹饪', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (714, 'qRV5nI3NaW5OXmTK5p0foI', 2, '平底锅烧热，加入植物油，煎制牛肉直至表面焦黄色（可以带生，千万别糊了），取出备用。

💡 提示：煎牛肉时火候不宜过大，以免外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (715, 'qRV5nI3NaW5OXmTK5p0foI', 3, '汤锅烧热，加入橄榄油，放入洋葱丁、胡萝卜丁、欧芹丁炒至洋葱透明，加入番茄膏和番茄罐头，翻炒均匀。

💡 提示：炒洋葱时火候要适中，避免炒糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (716, 'qRV5nI3NaW5OXmTK5p0foI', 4, '加入煎好的牛肉和马铃薯块，翻炒均匀，加水没过食材，大火烧开后撇去浮沫，转中小火加盖炖煮1小时。

💡 提示：撇去浮沫可以使汤更清澈，口感更好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (717, 'qRV5nI3NaW5OXmTK5p0foI', 5, '开盖加入包菜片和红肠块，搅拌均匀，继续中小火炖煮半小时。

💡 提示：最后加入包菜和红肠，以保持其口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (718, 'qRV5nI3NaW5OXmTK5p0foI', 6, '开盖加入剩余60g盐，混合均匀后盛盘。

💡 提示：调味时可根据个人口味调整盐量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (719, 'lgsrTbt3WwGBq9mgUIbbyE', 1, '提前洗净好绿豆、红豆、花生、黄豆、豌豆、红腰豆，并用干净的玻璃碗盛放好，注入3/4玻璃碗大小的饮用水，浸泡一夜（或最少8小时）。

💡 提示：确保豆类充分吸水，煮时更容易熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (720, 'lgsrTbt3WwGBq9mgUIbbyE', 2, '提前洗净好大米、糯米、薏米、黑米、小米、莲子，并用干净的玻璃碗盛放好，注入3/4玻璃碗大小的饮用水，浸泡3小时。

💡 提示：米类和莲子也需要充分吸水，以保证煮出的粥更加软糯。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (721, 'lgsrTbt3WwGBq9mgUIbbyE', 3, '将步骤1中准备好的盛有绿豆、红豆、花生、黄豆、豌豆、红腰豆的玻璃碗中的水分分离倒出，其余原料倒入粥锅中，加入1升饮用水（或漫过食材1厘米），大火煮沸，煮沸后合上锅盖，小火煮30分钟。

💡 提示：煮沸后转小火，避免溢锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (722, 'lgsrTbt3WwGBq9mgUIbbyE', 4, '将步骤2中准备好的盛有大米、糯米、薏米、黑米、小米、莲子的玻璃碗中的水分分离倒出，其余原料继续倒入粥锅中，合上锅盖，小火煮60分钟。

💡 提示：定时搅拌，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (723, 'lgsrTbt3WwGBq9mgUIbbyE', 5, '洗净好红枣、桂圆、栗子、核桃、葡萄干（其中红枣切成小片）、冰糖，倒入锅中，合上锅盖，小火煮60分钟。

💡 提示：最后加入这些食材，保持其口感和香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (724, 'lgsrTbt3WwGBq9mgUIbbyE', 6, '确认煮出的粥粘稠后即可关火、盛盘、食用。

💡 提示：可以用勺子舀起一些粥，如果能挂在勺背上，说明已经足够粘稠。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (725, 'Gj108A79IZZuwXVKCf1fuI', 1, '将西红柿洗净，切成小块。

💡 提示：西红柿切块时尽量保持大小均匀，以便烹饪时受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (726, 'Gj108A79IZZuwXVKCf1fuI', 2, '将葱、姜、蒜分别切碎备用。

💡 提示：切碎的葱姜蒜可以更好地释放香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (727, 'Gj108A79IZZuwXVKCf1fuI', 3, '将鸡蛋打入碗中，用筷子或打蛋器搅拌均匀。

💡 提示：充分搅拌可以使鸡蛋更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (728, 'Gj108A79IZZuwXVKCf1fuI', 4, '热锅后倒入15毫升食用油，待油温升至六成热（约180℃），放入葱姜蒜翻炒30秒。

💡 提示：油温不宜过高，以免葱姜蒜炒焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (729, 'Gj108A79IZZuwXVKCf1fuI', 5, '加入西红柿块，翻炒1分钟，使其出汁。

💡 提示：西红柿炒至出汁后再加水，汤会更加鲜美。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (730, 'Gj108A79IZZuwXVKCf1fuI', 6, '倒入适量清水，水量约为锅内食材高度的1.2倍，加入5克盐，大火烧开。

💡 提示：加水后要大火烧开，使汤的味道更加浓郁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (731, 'Gj108A79IZZuwXVKCf1fuI', 7, '待汤烧开后，慢慢倒入打好的鸡蛋液，并用筷子迅速搅散，形成蛋花。

💡 提示：倒鸡蛋液时要慢慢倒入并迅速搅散，这样形成的蛋花更漂亮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (732, 'Gj108A79IZZuwXVKCf1fuI', 8, '最后加入味素和2滴香油，再煮30秒即可关火出锅。

💡 提示：味素和香油在最后加入，以保持其香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (733, '4qgwBig292Eihhc9xD9lQj', 1, '将金针菇徒手掰散，越散越好，以免藏牙。然后用清水洗净，沥干备用。

💡 提示：掰散金针菇时尽量细致，避免有大块残留', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (734, '4qgwBig292Eihhc9xD9lQj', 2, '用菜刀或者水果刀将金针菇切成段，长度不超过5厘米。

💡 提示：切段时保持均匀，便于烹饪和食用', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (735, '4qgwBig292Eihhc9xD9lQj', 3, '将切好的金针菇放入锅中，加入约1.5升水，大火烧开后撇去浮沫。

💡 提示：撇去浮沫可以使汤更清澈', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (736, '4qgwBig292Eihhc9xD9lQj', 4, '如果喜欢在汤里加入鸡蛋，可在水沸腾之后将打散的鸡蛋液缓缓倒入锅中，边倒边搅拌，形成蛋花。

💡 提示：鸡蛋液要慢慢倒入，并不断搅拌，使蛋花更加细腻', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (737, '4qgwBig292Eihhc9xD9lQj', 5, '加入食盐和味精，搅拌均匀，继续加热至再次沸腾。

💡 提示：调味料要充分搅拌均匀，确保味道均匀分布', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (738, '4qgwBig292Eihhc9xD9lQj', 6, '关火，出锅前加入几滴香油增香，即可装盘上桌。

💡 提示：香油不要加太多，以免掩盖金针菇的鲜味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (739, '1foo36wy8vYnNVcFhCwGkH', 1, '将排骨用热水焯水，去除血水和杂质，捞出备用。

💡 提示：焯水时可以加入几片姜和少许料酒去腥', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (740, '1foo36wy8vYnNVcFhCwGkH', 2, '将陈皮、麦冬、玉竹、石斛和西洋参冲洗干净，备用。

💡 提示：确保药材表面无尘土', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (741, '1foo36wy8vYnNVcFhCwGkH', 3, '将煲汤盅洗净，先放入排骨在底部，然后依次放入陈皮、麦冬、玉竹、石斛和西洋参。

💡 提示：食材摆放顺序不影响最终味道，但建议先放不易煮烂的食材', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (742, '1foo36wy8vYnNVcFhCwGkH', 4, '加入热水至煲汤盅八分满，盖上盖子。

💡 提示：水不宜太满，以免溢出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (743, '1foo36wy8vYnNVcFhCwGkH', 5, '将煲汤盅放入炖锅中，隔水炖煮1.5小时。

💡 提示：使用小火慢炖，保持水温在90-100℃之间', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (744, '1foo36wy8vYnNVcFhCwGkH', 6, '炖煮完成后，加入食盐调味，趁热饮用。

💡 提示：调味时可尝一下汤的味道，根据个人口味适量加盐', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (745, 'OFr9czo9ujMvT18OSuo1bK', 1, '黄瓜洗净，切成0.5-1.2 mm厚的薄片

💡 提示：可用刮皮刀刮制更均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 2, '小葱洗净切末；大蒜拍松去皮，对半切', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (747, 'OFr9czo9ujMvT18OSuo1bK', 3, '皮蛋剥壳，每个切成6-8份

💡 提示：切前抹少许香油防粘刀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (748, 'OFr9czo9ujMvT18OSuo1bK', 4, '锅中倒入食用油，放入皮蛋块和大蒜，小火煸炒

💡 提示：至皮蛋和大蒜表面呈焦黄色', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 5, '加入水400-500 ml，转大火烧开', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (750, 'OFr9czo9ujMvT18OSuo1bK', 6, '放入黄瓜片，待水再次沸腾后立即关火

💡 提示：避免黄瓜过熟变软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 7, '加入盐、鸡精调味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('OFr9czo9ujMvT18OSuo1bK', 8, '盛入碗中，撒上葱花', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (753, 'zxuIFqiaL2poyEU2iicg66', 1, '将锅烧热后，加入25ml油，大火加热至油温约180℃（油面微微冒烟）。

💡 提示：确保锅和油充分预热，这样煎蛋时不会粘锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (754, 'zxuIFqiaL2poyEU2iicg66', 2, '打入两个鸡蛋，煎至底部完全凝固。

💡 提示：不要急于翻面，待底部凝固后再翻', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (755, 'zxuIFqiaL2poyEU2iicg66', 3, '翻面，继续煎至两面完全凝固。

💡 提示：保持中火，防止煎糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (756, 'zxuIFqiaL2poyEU2iicg66', 4, '关火，将煎好的鸡蛋取出，切成2-5cm²的小块后放回锅中（也可以直接用锅铲铲碎）。

💡 提示：切块大小适中，便于后续翻炒', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (757, 'zxuIFqiaL2poyEU2iicg66', 5, '重新开火，倒入160ml可乐、15ml生抽、7.5ml老抽、7.5ml豆瓣酱（可选）、5ml蚝油，搅拌均匀。

💡 提示：确保所有调料混合均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (758, 'zxuIFqiaL2poyEU2iicg66', 6, '大火加热至锅内液体剩1/3，大约需要3-5分钟。

💡 提示：注意观察液体量，避免烧干', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (759, 'zxuIFqiaL2poyEU2iicg66', 7, '倒入200g米饭和20-100g火腿肠丁，转中火翻炒均匀。

💡 提示：确保米饭和火腿肠均匀裹上酱汁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (760, 'zxuIFqiaL2poyEU2iicg66', 8, '改小火，在锅内食物中心挖一个洞，打入1个鸡蛋，盖上锅盖，焖2分钟。

💡 提示：挖洞打蛋可以使鸡蛋更好地融入炒饭', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (761, 'zxuIFqiaL2poyEU2iicg66', 9, '开盖翻炒至第三颗鸡蛋熟透，撒上5g葱花和1g胡椒粉，出锅。

💡 提示：翻炒均匀，使葱花和胡椒粉均匀分布', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (762, 'XXNovnHdbiL6PHWACvlkrj', 1, '若使用冬笋，切薄片后冷水下锅，煮沸后保持小火煮10分钟，捞出沥干

💡 提示：去涩味关键步骤，不可省略', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 2, '咸肉切1 cm见方小丁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (764, 'XXNovnHdbiL6PHWACvlkrj', 3, '冷锅加入10 g猪油、15 ml料酒、0–3 g白糖，放入咸肉丁（及焯好冬笋片），中小火煸炒至咸肉透明、表面微冒小泡

💡 提示：需持续翻动防焦，至咸肉丁边缘微金黄、油脂析出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (765, 'XXNovnHdbiL6PHWACvlkrj', 4, '青菜洗净，菜梗与菜叶分离；菜梗切0.5 cm边长正方形小块，菜叶切成长2–3 cm、宽1–1.5 cm长方形小块

💡 提示：分切确保熟度一致：菜梗耐炒，菜叶易熟', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (766, 'XXNovnHdbiL6PHWACvlkrj', 5, '热锅（可补少许油）下菜梗，中大火快速翻炒至颜色转为鲜亮翡翠色

💡 提示：避免过久致软烂，保持清脆口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('XXNovnHdbiL6PHWACvlkrj', 6, '大米淘净，倒入电饭煲内胆，加入按需求调整的水量（基础310 ml）', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (768, 'XXNovnHdbiL6PHWACvlkrj', 7, '将炒好的咸肉丁和菜梗均匀铺在生米表面，切勿搅拌

💡 提示：严禁搅匀，确保分层蒸煮结构', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (769, 'XXNovnHdbiL6PHWACvlkrj', 8, '启动电饭煲‘正常煮饭’模式（参考时长约25–35分钟，依机型而异）

💡 提示：以电饭煲自动跳至保温为准', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (770, 'XXNovnHdbiL6PHWACvlkrj', 9, '煮饭程序结束前10分钟，开盖迅速将切好的菜叶均匀铺于饭面

💡 提示：利用余汽焖熟菜叶，保持碧绿与嫩度', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (771, 'XXNovnHdbiL6PHWACvlkrj', 10, '煮饭程序结束后焖5分钟，开盖淋入剩余5 g猪油和1 g白胡椒粉，立即用饭勺从底向上快速、彻底翻拌均匀

💡 提示：趁热翻拌使油脂与香气充分融合，避免结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (772, 'O6gvFpJonEKyY0mDJTTtre', 1, '盆中加入所有面粉，加入芝麻香油，面粉中央挖小洞，分 4-5 次加入冷水，并搅和，当出现碎末状的稍微干燥面团时停止加水，用手将面团压实。

💡 提示：确保面团均匀吸收水分，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (773, 'O6gvFpJonEKyY0mDJTTtre', 2, '面团压实至可把盆周围的面粉纳入即可，此步骤为面光盆光。将面团置于桌上，盆倒扣于桌上，环境温度为 25 度，使面团醒发约 45 分钟。

💡 提示：醒发可以让面团更加柔软，便于擀皮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (774, 'O6gvFpJonEKyY0mDJTTtre', 3, '醒发完成后，将面团搓成条状，合成一团，再次搓成条，重复 3 次。擀成条状，切成 20 份均匀大小面团，并搓成直径约 3-3.5cm 的球状。

💡 提示：多次搓条可以使面团更均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (775, 'O6gvFpJonEKyY0mDJTTtre', 4, '压扁面团，在手上，桌上，擀面杖上，及面团上撒上面粉，防止面团发粘。用擀面杖将面团擀平，约 8cm 直径，厚约 2mm，中间略微比四周厚 1mm。

💡 提示：擀皮时要保持面皮边缘薄而中间略厚，这样包出来的饺子不易破皮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (776, 'O6gvFpJonEKyY0mDJTTtre', 5, '猪肉去皮,保留部分肥肉,切成小块。菜刀（建议两把）将猪肉剁成肉沫,放入碗中。葱、姜切成末,放入肉碗中搅拌均匀。韭菜洗净,切短至 3mm 以下长度。韭菜和肉沫混合,加入蚝油、生抽、香油各 2ml,加入一个鸡蛋的蛋清,用手混合搅拌均匀。放置 30 分钟即可开始包饺子。

💡 提示：馅料要充分搅拌均匀，使其更有弹性。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (777, 'O6gvFpJonEKyY0mDJTTtre', 6, '左手上放面皮，放饺子馅一面尽量不要粘到面粉，防止无法合拢。右手用筷子夹约面皮 1/2 直径的馅。沿饺子皮圆周进行合拢，捏实，个人吃无需捏花，饺子皮不漏即可。

💡 提示：包饺子时要注意封口紧密，防止煮的时候开裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (778, 'O6gvFpJonEKyY0mDJTTtre', 7, '使用可放下 20 只饺子的锅，或分批量煮。烧水，水约 3/4 锅的高度。大火烧开水后放入饺子，调至中火。第一次放入饺子，且水冒泡后，锅边加入 50ml 冷水（重复此步骤两次）。第三次水开后加入冷水 50ml，水开后调至小火等 60s 即可出锅。

💡 提示：煮饺子时加冷水可以防止饺子皮破裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (779, 'cY0eI9wrmP0LdabMk0j6Sq', 1, '将所有蔬菜和肉类材料洗净并切成适当大小的块状，确保边长不超过4cm。

💡 提示：切好的食材更容易煮熟，且口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (780, 'cY0eI9wrmP0LdabMk0j6Sq', 2, '如有生肉，先放入冷水中，盖上锅盖，大火煮沸后撇去浮沫，再关火捞出半熟的肉备用。

💡 提示：去除血沫可以使汤更加清澈，肉质也更嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (781, 'cY0eI9wrmP0LdabMk0j6Sq', 3, '在锅中加入800ml冷水，大火加热至沸腾。

💡 提示：水要足够多，以确保面条和其他食材都能充分煮熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (782, 'cY0eI9wrmP0LdabMk0j6Sq', 4, '将较难煮熟的食材（如半熟肉类、香菇）放入锅中，保持中火煮沸10分钟。

💡 提示：确保这些食材煮熟后再加入其他食材，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (783, 'cY0eI9wrmP0LdabMk0j6Sq', 5, '将面条放入锅中，适当搅拌确保面条和汤充分接触，保持轻微沸腾状态煮5分钟。加入面条后液面易产生白色泡沫，可适当抬起锅盖通气或者撤下锅盖。

💡 提示：适当搅拌可以防止面条粘连，同时使面条更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (784, 'cY0eI9wrmP0LdabMk0j6Sq', 6, '将易于煮熟的食材（如青菜、胡萝卜、青椒、番茄）放入锅中，适当搅拌以充分浸没，煮2-5分钟。

💡 提示：这些食材容易煮熟，不宜过早加入，以免煮烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (785, 'cY0eI9wrmP0LdabMk0j6Sq', 7, '关火，随后加入适量的盐、胡椒粉和香油调味，适当搅拌即可出锅食用。

💡 提示：调味料的用量根据个人口味调整，建议少量多次添加，以免过量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (786, 'BvobIsCMvJx11q4SJhIqry', 1, '锅中加水烧开，放入年糕煮熟，期间不断搅拌以防止粘连。煮熟后捞出年糕，用冷水冲洗并沥干水分备用。

💡 提示：煮年糕时要不断搅拌，以免粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (787, 'BvobIsCMvJx11q4SJhIqry', 2, '小葱切葱花，将葱白和葱叶分开；青菜切小段备用。

💡 提示：葱白和葱叶分开处理，便于后续烹饪。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (788, 'BvobIsCMvJx11q4SJhIqry', 3, '如果选择加入鸡蛋，可以先在另一个平底锅中热油，倒入打散的鸡蛋液，煎至金黄色后盛出备用。

💡 提示：煎蛋时火候不要太大，以免煎糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (789, 'BvobIsCMvJx11q4SJhIqry', 4, '热锅，加入30ml食用油，放入葱白，小火慢炸至大部分葱白变成焦黄色且发出香味，倒出葱油备用。

💡 提示：炸葱白时要用小火，避免炸糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (790, 'BvobIsCMvJx11q4SJhIqry', 5, '重新热锅，加入20ml食用油，放入所有辅料（如鸡蛋、青菜等），翻炒均匀。

💡 提示：辅料可以根据个人喜好添加，如瘦肉等。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (791, 'BvobIsCMvJx11q4SJhIqry', 6, '将年糕加入锅中，加入酱油和盐，大火快速翻炒均匀，使年糕充分吸收调味料。

💡 提示：翻炒时火候要大，动作要快，以免年糕粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (792, 'BvobIsCMvJx11q4SJhIqry', 7, '关火，加入之前炸好的葱油，翻炒均匀，使年糕表面更加光亮。

💡 提示：最后加入葱油可以使年糕更加香滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (793, 'BvobIsCMvJx11q4SJhIqry', 8, '将炒好的年糕盛出装盘，撒上葱叶即可享用。

💡 提示：葱叶可以在最后撒上，增加香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (794, 'DjNC1VVScw0BVHzrwniebT', 1, '将火腿肠撕开包装，切成宽度1cm的小块。

💡 提示：切得均匀可以让火腿肠受热更均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (795, 'DjNC1VVScw0BVHzrwniebT', 2, '向煮锅中加入300ml水，煮沸后加入方便面面饼，煮45秒。煮的过程中用筷子或叉子挑动面条，将其打散。

💡 提示：煮的时间不宜过长，以免面条过于软烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (796, 'DjNC1VVScw0BVHzrwniebT', 3, '面条打散后立刻关火，将面汤和面分离。用凉水冲一下面条，使其更加爽滑。

💡 提示：冷水冲洗可以去除多余的淀粉，使面条口感更好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (797, 'DjNC1VVScw0BVHzrwniebT', 4, '准备一个小碗，将方便面的调料包挤进去。挤进去所有菜包、酱包以及50%-80%的粉包（约10-16g）。将上一步的面汤取出80ml，加入小碗，搅匀，得到调料碗。

💡 提示：根据个人口味调整粉包的用量，避免过咸', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (798, 'DjNC1VVScw0BVHzrwniebT', 5, '取出一个鸡蛋打入一个小碗，加入2g盐，搅拌均匀。热锅20秒，加入8ml油，倒入鸡蛋液，翻炒大约20秒至鸡蛋形成固态即可。将煎鸡蛋取出暂存。

💡 提示：热锅冷油，中小火炒鸡蛋，避免糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (799, 'DjNC1VVScw0BVHzrwniebT', 6, '再次热锅20秒，增加锅内的油到10ml。加入第一步处理的火腿肠，翻炒10秒。

💡 提示：火腿肠炒至表面微焦，香味更浓', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (800, 'DjNC1VVScw0BVHzrwniebT', 7, '加入第二步处理好的面条，翻炒30秒。

💡 提示：保持中火，快速翻炒，避免面条粘锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (801, 'DjNC1VVScw0BVHzrwniebT', 8, '加入第四步调好的调料碗，翻炒30秒。

💡 提示：调料均匀裹在面条上，味道更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (802, 'DjNC1VVScw0BVHzrwniebT', 9, '加入第五步炒好的鸡蛋，翻炒30秒。

💡 提示：最后加入鸡蛋，保持其嫩滑口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (803, 'DjNC1VVScw0BVHzrwniebT', 10, '关火盛盘即可。在北京，可以考虑在盛盘后加入芝麻酱。如果芝麻酱太浓稠，可以1:1兑水稀释。

💡 提示：芝麻酱可以增加风味，但要适量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (804, 'QUVTjg1TEemQTefJl8abNw', 1, '将小葱切碎（葱白和葱叶分开）、蒜瓣拍碎，放在案板上备用。

💡 提示：确保葱白和葱叶分开，以便在不同步骤中使用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (805, 'QUVTjg1TEemQTefJl8abNw', 2, '打碎鸡蛋，捞一点蛋清到一只碗中，剩下的丢入另一只碗中备用。

💡 提示：蛋清用于腌制肉丝，蛋黄用于后续炒制。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (806, 'QUVTjg1TEemQTefJl8abNw', 3, '将绿豆芽放入锅中，大火煮60秒。豆芽捞出，过凉水，放入盘中备用。

💡 提示：焯水后的豆芽更加脆嫩，过凉水可以保持其爽脆口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (807, 'QUVTjg1TEemQTefJl8abNw', 4, '黄瓜切丝放入盘中备用，可和豆芽放在一起。

💡 提示：黄瓜丝要切得均匀，这样炒出来的河粉更美观。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (808, 'QUVTjg1TEemQTefJl8abNw', 5, '处理面筋，单独丢一个盘中。清洗面筋之后，请用手将面筋中的大量水分挤出（不需过于用力）。

💡 提示：挤干水分的面筋更容易吸收调味料，口感更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (809, 'QUVTjg1TEemQTefJl8abNw', 6, '肉切细条状，加入淀粉与刚刚碗中的鸡蛋清、胡椒粉，顺时针拌匀。

💡 提示：腌制肉丝时，顺时针搅拌可以使肉质更加嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (810, 'QUVTjg1TEemQTefJl8abNw', 7, '热锅冷油，加入食用油，锅热倒出，再倒入处理好的肉，翻炒均匀至变色，倒入碗中备用。

💡 提示：先热锅再加油，可以防止肉粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (811, 'QUVTjg1TEemQTefJl8abNw', 8, '趁锅热，加入20g食用油（高血压人群可降低用量），倒入葱白、蒜爆炒出香。

💡 提示：葱白和蒜要炒出香味，但不要炒焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (812, 'QUVTjg1TEemQTefJl8abNw', 9, '加入河粉，淋入老抽提色，翻炒均匀后再加入河粉炒料（或自制炒料），继续翻炒约2-3分钟。

💡 提示：翻炒时要均匀，避免河粉结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (813, 'QUVTjg1TEemQTefJl8abNw', 10, '河粉即将透明时，放入炒制好的肉丝与面筋，并加入生抽提鲜，简单翻炒两次，约1-2分钟。

💡 提示：肉丝和面筋要均匀分布在河粉中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (814, 'QUVTjg1TEemQTefJl8abNw', 11, '加入豆芽与黄瓜丝，翻炒至河粉完全透明，约2-3分钟。

💡 提示：最后加入蔬菜，保持其脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (815, 'QUVTjg1TEemQTefJl8abNw', 12, '关火！撒入葱叶点缀，把锅端起，倒入盘中，开始享用。

💡 提示：葱叶要在最后撒入，以保持其颜色和香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (816, '94dly9SOQdn3eYH7kAdMrZ', 1, '将馒头切成小块或小片。

💡 提示：馒头切得均匀一些，这样炒出来的口感更一致。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (817, '94dly9SOQdn3eYH7kAdMrZ', 2, '如果使用鸡蛋，将鸡蛋打进碗里，打散（可加盐和五香粉各1g或不加，等炒的过程中加）。

💡 提示：鸡蛋不宜过多，否则会粘成一团。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (818, '94dly9SOQdn3eYH7kAdMrZ', 3, '将打散的鸡蛋浇在馒头上，拌匀。

💡 提示：确保每一块馒头都裹上蛋液。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (819, '94dly9SOQdn3eYH7kAdMrZ', 4, '大火热锅，倒入食用油，烧至油热。

💡 提示：油温要高，这样炒出来的馍丁才会外酥里嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (820, '94dly9SOQdn3eYH7kAdMrZ', 5, '将馍丁放进去翻炒，翻炒均匀。

💡 提示：用铲子不断翻动，防止粘锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (821, '94dly9SOQdn3eYH7kAdMrZ', 6, '将火调小，继续翻炒至馍丁呈金黄色。

💡 提示：注意控制火候，防止炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (822, '94dly9SOQdn3eYH7kAdMrZ', 7, '放入盐、孜然粉、辣椒粉和五香粉，翻炒均匀。

💡 提示：调味料要均匀撒在馍丁上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (823, '94dly9SOQdn3eYH7kAdMrZ', 8, '最后将葱花放入一起翻炒几下。

💡 提示：葱花不要炒太久，保持鲜绿色。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (824, '94dly9SOQdn3eYH7kAdMrZ', 9, '关火出锅，装盘即可。

💡 提示：趁热食用，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (825, 'egBykH5NBt0XSPSKMUpNxo', 1, '将黄瓜、白菜、胡萝卜分别切成细丝，备用。

💡 提示：切丝要均匀，这样口感更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (826, 'egBykH5NBt0XSPSKMUpNxo', 2, '将葱切碎，蒜切末，备用。

💡 提示：葱和蒜切得越细越好，更容易出香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (827, 'egBykH5NBt0XSPSKMUpNxo', 3, '热锅凉油，油温五成热时下入葱花和蒜末，炒出香味后加入肉丁，翻炒至肉丁变色。

💡 提示：肉丁要炒至完全变色，无红色血丝。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (828, 'egBykH5NBt0XSPSKMUpNxo', 4, '加入豆瓣酱和甜面酱，继续翻炒，加入1汤匙料酒和5g糖，炒至酱料微微粘稠。

💡 提示：用中小火慢炒，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (829, 'egBykH5NBt0XSPSKMUpNxo', 5, '取一个大碗，加入适量凉水，备用。

💡 提示：凉水可以迅速冷却面条，保持其劲道口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (830, 'egBykH5NBt0XSPSKMUpNxo', 6, '另起一锅，加水烧开后放入面条，煮至断生（无白芯），捞出后立即放入第5步准备的凉水中过凉。

💡 提示：煮面时要不断搅拌，防止粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (831, 'egBykH5NBt0XSPSKMUpNxo', 7, '将过凉后的面条捞出，控干水分，放入干净的碗中。

💡 提示：尽量控干水分，以免影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (832, 'egBykH5NBt0XSPSKMUpNxo', 8, '将炒好的炸酱倒入面条中，拌匀。然后加入切好的黄瓜丝、白菜丝、胡萝卜丝，再次拌匀即可。

💡 提示：拌匀时要充分，让每一根面条都裹上酱汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (833, '66pqGD6D2cIVfJg3WmAKAj', 1, '将锅中的水煮沸，加入250g碱水面，焯烫25秒钟后捞起。

💡 提示：焯烫时间不宜过长，以免面条过于软烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (834, '66pqGD6D2cIVfJg3WmAKAj', 2, '将焯好的面条放入碗中，加入3g食盐、0-3g鸡精和0.5-1g胡椒粉，拌匀。

💡 提示：趁热拌匀，使调料均匀附着在面条上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (835, '66pqGD6D2cIVfJg3WmAKAj', 3, '将40ml芝麻酱用90ml温水稀释，搅拌均匀后倒入面条中。

💡 提示：芝麻酱要充分稀释，避免结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (836, '66pqGD6D2cIVfJg3WmAKAj', 4, '加入5ml酱油、30ml肉汤汁和30ml蒜水，拌匀。

💡 提示：肉汤汁和蒜水可以增加面条的风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (837, '66pqGD6D2cIVfJg3WmAKAj', 5, '加入50g萝卜干、30g炒熟的肉末、20g酸豆角和10g葱花。

💡 提示：配料可以根据个人喜好调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (838, '66pqGD6D2cIVfJg3WmAKAj', 6, '最后根据个人口味加入0-10ml辣椒油，拌匀即可食用。

💡 提示：辣椒油可以增加辣味，不喜欢辣的可以不加。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (839, 'U0n3JIx4Ou4AEyF7hLRQD8', 1, '取一只鸡腿，鸡皮朝下放在砧板上，用刀尖沿着鸡腿骨头的轮廓轻轻划开，从一端到另一端。

💡 提示：刀要锋利，动作要轻柔，避免割伤手', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (840, 'U0n3JIx4Ou4AEyF7hLRQD8', 2, '用手指或刀背慢慢推开鸡肉，让骨头暴露出来。如果遇到筋膜，用刀尖切断。

💡 提示：耐心操作，确保鸡肉完全分离', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (841, 'U0n3JIx4Ou4AEyF7hLRQD8', 3, '当鸡肉完全分离后，握住骨头一端，轻轻扭转并拔出。

💡 提示：用力要均匀，避免撕裂鸡肉', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (842, 'U0n3JIx4Ou4AEyF7hLRQD8', 4, '重复上述步骤将所有鸡腿去骨。

💡 提示：每只鸡腿去骨时间约为3分钟', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (843, 'U0n3JIx4Ou4AEyF7hLRQD8', 5, '去骨鸡腿加入黑胡椒粉、黑胡椒碎、盐、姜片腌制5分钟。

💡 提示：腌制时间不宜过长，以免鸡肉变硬', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (844, 'U0n3JIx4Ou4AEyF7hLRQD8', 6, '碗里加入料酒、生抽、蜂蜜、老抽、清水拌匀，调成酱汁。

💡 提示：确保调料充分混合均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (845, 'U0n3JIx4Ou4AEyF7hLRQD8', 7, '锅中加水烧开，放入西兰花和胡萝卜焯水1-2分钟，捞起沥干备用。

💡 提示：水中可加少许盐，使蔬菜颜色更鲜艳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (846, 'U0n3JIx4Ou4AEyF7hLRQD8', 8, '热锅放油15ml，放入大蒜爆香。

💡 提示：火候不要太大，以免大蒜焦糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (847, 'U0n3JIx4Ou4AEyF7hLRQD8', 9, '放入鸡腿，中小火煎至两面金黄，每面约3-4分钟。如果感觉锅中太干，补5-10ml油。

💡 提示：煎制时火力要适中，避免外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (848, 'U0n3JIx4Ou4AEyF7hLRQD8', 10, '加入调好的酱汁，盖好盖子中小火焖煮5-10分钟，直至鸡腿熟透，酱汁浓稠起泡即可。

💡 提示：焖煮时每隔3-5分钟翻搅一下，避免局部过热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (849, 'U0n3JIx4Ou4AEyF7hLRQD8', 11, '将鸡腿切件，和蔬菜一起摆在饭面上，淋入煎鸡腿的酱汁，即可享用。

💡 提示：切件时注意保持鸡腿完整，美观', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (850, 'TVhdKDeR3a3a69XPQ5hC7d', 1, '将水倒入锅中，大火加热至沸腾。

💡 提示：使用热水可以更快达到沸腾状态。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (851, 'TVhdKDeR3a3a69XPQ5hC7d', 2, '将泡面面饼放入沸水中。

💡 提示：确保面饼完全浸入水中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (852, 'TVhdKDeR3a3a69XPQ5hC7d', 3, '加入泡面附带的佐料，用筷子轻轻搅拌，使佐料充分溶解。

💡 提示：搅拌时注意不要把面条弄碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (853, 'TVhdKDeR3a3a69XPQ5hC7d', 4, '盖上锅盖，等待约1分钟至锅内水再次沸腾。

💡 提示：保持中小火，防止水溢出。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (854, 'TVhdKDeR3a3a69XPQ5hC7d', 5, '打入一个鸡蛋到锅中，轻轻搅动几下，防止粘底。

💡 提示：如果喜欢全熟蛋，可以先将鸡蛋打散再倒入锅中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (855, 'TVhdKDeR3a3a69XPQ5hC7d', 6, '继续煮约3-4分钟，直到面条变软且鸡蛋达到你喜欢的熟度。

💡 提示：如果喜欢溏心蛋，可以减少煮的时间；如果喜欢全熟蛋，可以增加煮的时间。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (856, 'TVhdKDeR3a3a69XPQ5hC7d', 7, '关火，将煮好的泡面和蛋盛入碗中。

💡 提示：小心烫手。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (857, '8MpHhyNvCn3xsLjhF1ZFPk', 1, '将猪油放入碗中，如果猪油是固态的，可以将其放在微波炉中加热几秒钟至融化。

💡 提示：猪油融化后更容易均匀地包裹住米饭。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (858, '8MpHhyNvCn3xsLjhF1ZFPk', 2, '将热腾腾的米饭加入碗中，趁热搅拌均匀，使米饭充分吸收猪油。

💡 提示：米饭最好是刚煮好的，温度较高时更易吸收调味料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (859, '8MpHhyNvCn3xsLjhF1ZFPk', 3, '淋上生抽、老抽和蚝油（如果使用），继续搅拌均匀。

💡 提示：调味料要均匀分布，确保每粒米饭都能沾上调味料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (860, '8MpHhyNvCn3xsLjhF1ZFPk', 4, '撒上葱花和猪油渣（如果使用），再次轻轻拌匀。

💡 提示：葱花和猪油渣可以增加香气和口感，但不要过度搅拌以免破坏米饭的结构。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (861, 'D7A8t66w8F3HQEKQzd79AO', 1, '将1升水倒入锅中并煮沸

💡 提示：确保水完全沸腾后再下面条', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (862, 'D7A8t66w8F3HQEKQzd79AO', 2, '将120克挂面均匀放入锅中

💡 提示：用筷子轻轻拨散面条，防止粘连', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (863, 'D7A8t66w8F3HQEKQzd79AO', 3, '在煮的过程中不断搅拌面条，避免粘成一坨

💡 提示：保持中小火，防止水溢出', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (864, 'D7A8t66w8F3HQEKQzd79AO', 4, '当用筷子挑起一根面条且该面条能自然地从筷子上滑落时再等30秒关火

💡 提示：面条应煮至软硬适中，不要过于软烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (865, 'D7A8t66w8F3HQEKQzd79AO', 5, '将面条捞出，过冷水后沥干水分

💡 提示：过冷水可以使面条更加爽滑，不易粘连', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (866, 'D7A8t66w8F3HQEKQzd79AO', 6, '将面条放入碗中

💡 提示：可以先在碗底铺一层老干妈辣椒酱，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (867, 'D7A8t66w8F3HQEKQzd79AO', 7, '按照上面的计量放入1汤匙老干妈辣椒酱和1茶匙酱油

💡 提示：可以根据个人口味适量增减调料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (868, 'D7A8t66w8F3HQEKQzd79AO', 8, '用筷子将碗里的面条、老干妈辣椒酱和酱油拌均匀

💡 提示：充分拌匀，使每根面条都裹上调料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (869, 'yLxZNUOIKIazemIiXpMKml', 1, '提前将米饭煮好，约需20-30分钟。使用买米赠送的量杯，一杯米约为240g。

💡 提示：米饭可以提前一天煮好，冷藏保存，第二天加热即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (870, 'yLxZNUOIKIazemIiXpMKml', 2, '在锅中加入30ml油，开中火，放入300g猪肉馅，煎至两面微焦。

💡 提示：煎肉时不要频繁翻动，以免肉馅散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (871, 'yLxZNUOIKIazemIiXpMKml', 3, '将4个鸡蛋打入锅中，不要打散，盖上锅盖，小火焖煮2-3分钟，使蛋白凝固。

💡 提示：鸡蛋打入锅中后不要立即搅拌，保持完整形状更美观。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (872, 'yLxZNUOIKIazemIiXpMKml', 4, '调一个碗汁：在碗中加入10ml老抽、25ml生抽、20ml醋、15g糖和10g红葱油（可选），搅拌均匀。

💡 提示：碗汁可以根据个人口味适当调整比例。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (873, 'yLxZNUOIKIazemIiXpMKml', 5, '打开锅盖，将调好的碗汁倒入锅中，转大火收汁，等待3分钟，期间可轻轻翻动肉和鸡蛋，使其均匀裹上酱汁。

💡 提示：收汁时注意观察，避免烧焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (874, 'yLxZNUOIKIazemIiXpMKml', 6, '关火，将煎好的肉和鸡蛋盖到米饭上，撒上切碎的葱花。

💡 提示：葱花可以增加香气，提升口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (875, 'KEpE0f2AkjorCW6VmAaL0g', 1, '将小葱洗净，切成长约5–7 cm的段；葱白与葱绿分开放置。

💡 提示：葱白耐热，先下锅；葱绿易焦，后放。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (876, 'KEpE0f2AkjorCW6VmAaL0g', 2, '锅中倒入100 ml食用油，中火烧热后放入葱白段，煸炒至微黄。

💡 提示：油温约120°C，避免大火导致焦苦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (877, 'KEpE0f2AkjorCW6VmAaL0g', 3, '转小火，加入葱绿段，持续小火煸炒15–20分钟，直至葱段呈焦黄酥脆状。

💡 提示：全程小火、耐心翻动，防止糊锅；香味随时间充分释放。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (878, 'KEpE0f2AkjorCW6VmAaL0g', 4, '用漏勺捞出焦葱段（沥油备用），保留锅中葱油。

💡 提示：炸葱段可冷藏保存，拌面时撒入增香增脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (879, 'KEpE0f2AkjorCW6VmAaL0g', 5, '在锅中葱油里加入60 ml生抽、20 ml老抽、15 g白糖，小火加热并搅拌约1分钟，至糖完全溶解、酱汁均匀。

💡 提示：不可煮沸或久煮，以免酱油发苦；立即关火。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (880, 'KEpE0f2AkjorCW6VmAaL0g', 6, '将葱油酱汁倒入干净容器，冷却后密封，冷藏保存。

💡 提示：完全冷却后再密封，避免冷凝水影响保质期。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (881, 'KEpE0f2AkjorCW6VmAaL0g', 7, '取80 g干面条，放入1000 ml沸水中，按包装说明煮制（常规干面约3–5分钟）至熟透、无硬芯。

💡 提示：煮面水中可加少许盐或油防粘；勿过度煮软。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (882, 'KEpE0f2AkjorCW6VmAaL0g', 8, '将煮好的面条迅速捞出，沥干水分，放入碗中。

💡 提示：可过一次凉开水或冰水保持爽滑（非必需，依口感偏好）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (883, 'KEpE0f2AkjorCW6VmAaL0g', 9, '向面条中加入15 ml已制好的葱油酱汁，可选加入适量炸葱段，用筷子快速拌匀。

💡 提示：趁热拌面更易挂汁；酱汁遇热激发香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (884, 'cNp0IOSzIvZOGpR5VvVClr', 1, '炒锅烧热至冒烟，倒入3ml食用油滑锅后倒出底油；重新加入食用油，下五花肉片、葱片、姜丝、蒜粒、干红椒、花椒（如使用），中火匀速翻炒1分钟

💡 提示：全程不停匀速翻炒，避免粘锅或焦糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (885, 'cNp0IOSzIvZOGpR5VvVClr', 2, '沿锅边淋入料酒，加入生抽、老抽，继续翻炒1分钟

💡 提示：激发酒香，使肉片均匀上色', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (886, 'cNp0IOSzIvZOGpR5VvVClr', 3, '倒入500ml热水，盖上锅盖，中火炖煮3分钟

💡 提示：水需为热水，避免肉质骤冷收缩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (887, 'cNp0IOSzIvZOGpR5VvVClr', 4, '打开锅盖，加入芹菜段、青椒（如使用），调入盐、五香粉，盖上锅盖继续炖煮3分钟，关火备用

💡 提示：青椒不宜久煮，保持脆感；此步完成即为‘卤汁’与‘菜肉’混合体', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (888, 'cNp0IOSzIvZOGpR5VvVClr', 5, '蒸锅中加入1000ml水，大火烧开至充分上汽

💡 提示：确保水足、汽旺，避免中途加水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (889, 'cNp0IOSzIvZOGpR5VvVClr', 6, '将鲜面条均匀摊平在笼屉上，放入蒸锅，盖盖蒸15分钟

💡 提示：面条务必散开铺平，避免堆叠；过长可手动拽断', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (890, 'cNp0IOSzIvZOGpR5VvVClr', 7, '取出蒸熟的面条，立即用筷子和手（或锅铲辅助）彻底扒拉散开，平铺于案板上室温冷却

💡 提示：及时散热防粘连，为后续拌卤做准备', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (891, 'cNp0IOSzIvZOGpR5VvVClr', 8, '将冷却后的面条倒入卤菜锅中，一手持筷、一手持锅铲，将菜与卤汁反复翻覆至面条全部均匀上色

💡 提示：目标：每根面条裹满卤汁，无干粉、无结团', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (892, 'cNp0IOSzIvZOGpR5VvVClr', 9, '将拌匀的面条再次均匀铺在笼屉上，放入已上汽的蒸锅，盖盖蒸10分钟

💡 提示：二次蒸制使面条彻底吸味、软硬适中、香气融合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (893, 'ccNWBO22fuV22WWop1nt0M', 1, '将洋葱、胡萝卜、火腿肠或鸡胸肉切成小丁，备用。

💡 提示：切丁大小均匀，利于快炒熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (894, 'ccNWBO22fuV22WWop1nt0M', 2, '热锅，倒入10ml食用油，加热10秒。

💡 提示：油温不宜过高，避免后续食材焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 3, '放入洋葱丁翻炒1分钟至出香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 4, '加入胡萝卜、玉米粒、青豆，继续翻炒2分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (897, 'ccNWBO22fuV22WWop1nt0M', 5, '加入火腿肠或鸡胸肉丁，炒至变色。

💡 提示：确保肉类完全熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (898, 'ccNWBO22fuV22WWop1nt0M', 6, '加入米饭炒散，再加入20ml番茄酱，翻炒均匀至炒饭均匀上色、粒粒分明。

💡 提示：用铲背轻压结块米饭，助其散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 7, '将炒饭盛出备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (900, 'ccNWBO22fuV22WWop1nt0M', 8, '鸡蛋打散，加入10ml牛奶搅匀。

💡 提示：充分搅打至蛋液微起泡，口感更嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (901, 'ccNWBO22fuV22WWop1nt0M', 9, '锅中放入5ml食用油，倒入蛋液，轻晃锅底使蛋液均匀铺满锅面。

💡 提示：使用平底不粘锅效果更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (902, 'ccNWBO22fuV22WWop1nt0M', 10, '用小火加热，待蛋液表面呈半凝固状态（约30–60秒）时，将炒饭置于蛋液中央。

💡 提示：火力务必调小，避免底部焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (903, 'ccNWBO22fuV22WWop1nt0M', 11, '用锅铲小心将蛋皮边缘向内折叠，包裹住炒饭，形成椭圆形状。

💡 提示：若不擅长包裹，可改用‘盖被式’：将炒饭铺盘后淋上半熟蛋液，稍焖定型。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('ccNWBO22fuV22WWop1nt0M', 12, '用锅铲轻轻推至盘中，整理外形，并在表面挤少量番茄酱装饰。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (905, 'tcHBRWKIKXMldECgi6e7vd', 1, '将冷饭用铲子铲成小块，备用。

💡 提示：确保米饭松散，无结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (906, 'tcHBRWKIKXMldECgi6e7vd', 2, '将火腿、胡萝卜、黄瓜和熟肉切成小丁，香葱切碎，备用。

💡 提示：切丁大小均匀，便于翻炒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (907, 'tcHBRWKIKXMldECgi6e7vd', 3, '将鸡蛋打入碗中，搅匀。

💡 提示：不需要分离蛋白和蛋黄，直接搅匀即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (908, 'tcHBRWKIKXMldECgi6e7vd', 4, '大火热锅，待锅里冒烟后放入2汤匙食用油。

💡 提示：油温要高，这样炒出来的蛋更嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (909, 'tcHBRWKIKXMldECgi6e7vd', 5, '倒入搅匀的鸡蛋液，待主体凝固后迅速翻炒几下，盛出备用。

💡 提示：不要炒得太老，保持嫩滑。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (910, 'tcHBRWKIKXMldECgi6e7vd', 6, '在锅中留少许底油，或再加一些油，放入火腿、熟肉、胡萝卜和黄瓜丁，大火快速翻炒约1分钟。

💡 提示：爆香食材，使其更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (911, 'tcHBRWKIKXMldECgi6e7vd', 7, '将炒好的鸡蛋重新倒入锅中，翻炒均匀，然后加入冷饭，大火快速翻炒，使每一粒饭都裹上鸡蛋。

💡 提示：用铲子将饭块捣碎，确保米饭粒粒分明。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (912, 'tcHBRWKIKXMldECgi6e7vd', 8, '调至中小火，加入1/2茶匙盐、1/4茶匙胡椒粉和1汤匙生抽，继续翻炒均匀。

💡 提示：调味料要均匀分布，尝一下味道，根据个人口味调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (913, 'tcHBRWKIKXMldECgi6e7vd', 9, '最后加入切碎的香葱，快速翻炒10秒。

💡 提示：香葱要最后加入，以保持其香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (914, 'tcHBRWKIKXMldECgi6e7vd', 10, '关火，将炒好的蛋炒饭盛入碗中，即可享用。

💡 提示：趁热食用，口感最佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (915, 'bTRUTLGno6reUGPr9O36Mh', 1, '将锅中加入1L水，大火烧开。

💡 提示：确保水完全沸腾后再下米粉', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (916, 'bTRUTLGno6reUGPr9O36Mh', 2, '将袋装螺蛳粉中的米粉放入沸水中，用筷子轻轻搅拌，防止粘连。煮3-5分钟，直到米粉变软但仍有嚼劲。

💡 提示：根据个人喜好调整煮的时间，喜欢更有嚼劲的可以缩短时间', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (917, 'bTRUTLGno6reUGPr9O36Mh', 3, '将煮好的米粉捞出，过冷水后沥干水分，备用。

💡 提示：过冷水可以让米粉更加爽滑', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (918, 'bTRUTLGno6reUGPr9O36Mh', 4, '在锅中重新加入适量热水，放入汤料包，小火煮2-3分钟，让汤料充分溶解。

💡 提示：汤料包可以根据个人口味调整用量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (919, 'bTRUTLGno6reUGPr9O36Mh', 5, '将需要煮熟的配料包（如木耳、花生、螺蛳肉等）放入锅中，继续煮2-3分钟，使其入味。

💡 提示：这些配料需要稍微煮一下才能更好地吸收汤汁的味道', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (920, 'bTRUTLGno6reUGPr9O36Mh', 6, '将煮好的米粉放入碗中，倒入煮好的汤料和配料。

💡 提示：注意不要烫伤', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (921, 'bTRUTLGno6reUGPr9O36Mh', 7, '将不需要煮的配料包（如酸笋、豆皮等）直接撒在米粉上。

💡 提示：这些配料不宜久煮，以免失去脆嫩口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (922, 'bTRUTLGno6reUGPr9O36Mh', 8, '根据个人口味，加入醋包和辣椒油调味。

💡 提示：调味品的用量可以根据个人喜好调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (923, 'bTRUTLGno6reUGPr9O36Mh', 9, '搅拌均匀后即可享用。

💡 提示：趁热食用更美味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (924, 'bNFLahw70jtfmBkPMt7qWw', 1, '将一口深度约3/5的锅中加入足够的水，烧开。

💡 提示：确保水量足够，避免煮制过程中水分蒸发过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (925, 'bNFLahw70jtfmBkPMt7qWw', 2, '水沸腾后加入提前浸泡好的蕨根粉，中小火煮8分钟。

💡 提示：中小火煮制可以防止蕨根粉粘连，同时保证其熟透。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (926, 'bNFLahw70jtfmBkPMt7qWw', 3, '将煮好的蕨根粉捞出，立即放入冷水中过凉，约1-2分钟。

💡 提示：过冷水可以使蕨根粉迅速降温，防止粘连，并使其口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (927, 'bNFLahw70jtfmBkPMt7qWw', 4, '在一个碗中，按照比例加入酱油、香醋和油泼辣子，搅拌均匀。

💡 提示：根据个人口味调整酱料的比例，确保味道均衡。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (928, 'bNFLahw70jtfmBkPMt7qWw', 5, '尝一口调好的酱料，如果觉得酱油味稍浓，加入适量盐；如果不够鲜，加入适量糖，充分搅拌至调料溶解。

💡 提示：调味时要少量多次，逐步调整至满意的味道。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (929, 'bNFLahw70jtfmBkPMt7qWw', 6, '将过好冷水的蕨根粉捞出，沥干水分，放入调好的酱料中，充分搅拌均匀。

💡 提示：确保每根蕨根粉都裹上酱料，使味道更加均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (930, 'bNFLahw70jtfmBkPMt7qWw', 7, '将切好的葱、蒜、小米辣撒在蕨根粉上。

💡 提示：这些调料可以增添风味，但不加也无妨。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (931, 'FPvRQiJ2fmllAiOAuzeToo', 1, '将600毫升水倒入锅中并煮沸

💡 提示：确保水完全沸腾后再放入小汤圆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (932, 'FPvRQiJ2fmllAiOAuzeToo', 2, '放入250克小汤圆，用中小火煮8分钟

💡 提示：期间要不时搅拌，防止小汤圆粘底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (933, 'FPvRQiJ2fmllAiOAuzeToo', 3, '加入50克醪糟和10颗枸杞，继续煮2分钟

💡 提示：醪糟不要煮太久，以免香气挥发', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (934, 'FPvRQiJ2fmllAiOAuzeToo', 4, '关火后，盛入碗中，根据个人口味加入30-50克白糖并搅拌均匀

💡 提示：趁热食用风味更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (935, 'gzw6pJNEY5UXqrMjOeziTQ', 1, '将面粉放入大碗中，慢慢加入水，边加边搅拌，直至面团光滑不粘手。盖上湿布静置30分钟。

💡 提示：面团软硬度适中，不要太硬也不要太软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (936, 'gzw6pJNEY5UXqrMjOeziTQ', 2, '韭菜洗净切碎，鸡蛋打散成蛋液，虾仁用少许盐腌制10分钟。

💡 提示：韭菜切碎后可以撒一点盐，挤出多余的水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (937, 'gzw6pJNEY5UXqrMjOeziTQ', 3, '将切好的韭菜、腌制好的虾仁和蛋液混合，加入香油和盐，搅拌均匀。

💡 提示：搅拌时要均匀，确保所有食材充分混合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (938, 'gzw6pJNEY5UXqrMjOeziTQ', 4, '将面团分成小剂子，每个约30g，擀成薄圆饼。

💡 提示：擀皮时尽量保持厚度均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (939, 'gzw6pJNEY5UXqrMjOeziTQ', 5, '在每张饼皮中间放上适量的韭菜虾仁馅料，对折捏紧边缘封口。

💡 提示：封口要捏紧，防止煎的时候漏馅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (940, 'gzw6pJNEY5UXqrMjOeziTQ', 6, '热锅倒入适量食用油，放入包好的韭菜盒子，中小火煎至两面金黄，每面约2-3分钟。

💡 提示：煎制时火候不宜过大，以免外焦内生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (941, 'EGBwJCSSrHneS5BRZrGiYy', 1, '【低脂版预处理】将1.2g复配食品增稠剂（或2g玉米淀粉）加入10mL冷水中调匀成糊，再加入25mL开水搅匀至半透明凝胶状，冷却备用。

💡 提示：凝胶需完全冷却后再混入肉糜，避免烫熟肉末', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (942, 'EGBwJCSSrHneS5BRZrGiYy', 2, '将猪肉末、生姜末、葱末放入大碗中，加入生抽、料酒、盐、糖、白胡椒粉，沿同一方向持续搅拌5–8分钟至肉馅上劲、粘稠有弹性。

💡 提示：绞肉建议中档，保持颗粒感；虎口收口前可抹少许油防粘', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 3, '【高汤/浓汤宝处理】若用浓汤宝：取6g浓汤宝加15mL热水搅匀至乳浊液完全分散，再加入15mL常温水混合均匀；若用高汤，直接量取30mL。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (944, 'EGBwJCSSrHneS5BRZrGiYy', 4, '将高汤（或浓汤宝溶液）分2–3次缓慢加入肉馅，每次加后顺向搅打至完全吸收，直至馅料呈粘稠湿润状；若过稠，补5mL水继续搅打。

💡 提示：务必分次加，确保吸水均匀，避免出水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 5, '【低脂版】将冷却的增稠剂凝胶与280g瘦肉糜、15g融化猪油（或鸡油）混合拌匀；【常规版】跳过此步。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (946, 'EGBwJCSSrHneS5BRZrGiYy', 6, '加入冬笋丁、皮冻丁、香菇碎（及虾仁丁，若用），轻轻翻拌均匀；最后淋入芝麻油，拌匀。

💡 提示：皮冻需冷藏后切丁，否则易化；拌馅动作要轻，避免皮冻破碎出水', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (947, 'EGBwJCSSrHneS5BRZrGiYy', 7, '盖保鲜膜，冷藏静置30分钟，使味道融合、馅料紧实。

💡 提示：不可省略，直接影响成型与持汁性', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (948, 'EGBwJCSSrHneS5BRZrGiYy', 8, '取一张烧卖皮，中心放20–25g馅料；用虎口向上收拢边缘，捏出褶皱，形成‘花瓶’状，顶部自然开口，底部稍压平以利直立。

💡 提示：馅勿超量，否则蒸时爆裂；收口处可蘸少量水助粘合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('EGBwJCSSrHneS5BRZrGiYy', 9, '如用虾仁，在每个烧卖顶部轻按1颗完整虾仁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (950, 'EGBwJCSSrHneS5BRZrGiYy', 10, '将包好的烧卖间隔摆入已铺刷油竹垫/带孔硅油纸的蒸笼，留1.5cm空隙防粘连。

💡 提示：蒸笼需提前烧水至沸腾再上笼，防止皮塌', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (951, 'EGBwJCSSrHneS5BRZrGiYy', 11, '大火沸水蒸8–10分钟（鲜品）；冷冻品需蒸12–15分钟。关火后焖1分钟再揭盖。

💡 提示：蒸制时间严格把控，过久皮韧、皮冻全融；揭盖过早易塌陷', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (952, 'jmgNh1DyPrkoVWTMpPvMfT', 1, '将1升水倒入锅中，大火煮沸。如果喜欢面条更Q弹，可以在水中加入1/2茶匙盐。

💡 提示：加盐可以使面条更加有弹性', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (953, 'jmgNh1DyPrkoVWTMpPvMfT', 2, '水沸腾后，将快熟面放入锅中，用筷子轻轻拨散，防止粘连。

💡 提示：根据包装上的建议时间煮面，通常为3分钟左右', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (954, 'jmgNh1DyPrkoVWTMpPvMfT', 3, '当面条开始散开时，用筷子搅拌几下，确保面条受热均匀。

💡 提示：搅拌时要轻柔，避免面条断裂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (955, 'jmgNh1DyPrkoVWTMpPvMfT', 4, '用漏网将面条捞出，沥干水分，放入碗中。

💡 提示：尽量沥干水分，以免影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (956, 'jmgNh1DyPrkoVWTMpPvMfT', 5, '在面条上加入1汤匙麻油、1茶匙老抽、1/4茶匙胡椒粉和1/2茶匙生抽（可选），用筷子充分搅拌均匀。

💡 提示：搅拌时要确保调料均匀分布，使每根面条都裹上调料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (957, 'Z8gG88Xunen42wXePFCyFE', 1, '将娃娃菜和生菜洗净，切成适当大小，备用。

💡 提示：确保蔬菜洗净，去除杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (958, 'Z8gG88Xunen42wXePFCyFE', 2, '在直径18cm的小锅中加入500ml水，开大火烧开。

💡 提示：水要烧至沸腾', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (959, 'Z8gG88Xunen42wXePFCyFE', 3, '水开后，放入100g半干荞麦面和切好的娃娃菜，用筷子轻轻搅拌防止粘连。

💡 提示：面条和蔬菜同时下锅，可以节省时间', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (960, 'Z8gG88Xunen42wXePFCyFE', 4, '待水再次沸腾后，转小火，加入25g火锅底料、15g花生酱、150ml全脂牛奶、6ml生抽和10ml辣椒油，搅拌均匀。

💡 提示：小火慢炖可以使调料充分融合', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (961, 'Z8gG88Xunen42wXePFCyFE', 5, '继续小火煮5分钟，使面条和蔬菜充分吸收汤汁。

💡 提示：注意不要让汤汁煮干', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (962, 'Z8gG88Xunen42wXePFCyFE', 6, '加入切好的生菜，再煮2分钟。

💡 提示：生菜容易熟，最后加入即可', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (963, 'Z8gG88Xunen42wXePFCyFE', 7, '关火前，加入20ml醋和10ml花椒油，搅拌均匀。

💡 提示：醋和花椒油最后加入，保持香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (964, 'Z8gG88Xunen42wXePFCyFE', 8, '关火，直接端着小锅开吃。

💡 提示：趁热食用，味道更佳', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (965, 'vuj8XAePvKYuPSUnY7ZA5a', 1, '将油麦菜洗净，去掉老叶和根部，切成不超过4cm的小段。

💡 提示：清洗时可加入少量食盐，有助于去除农药残留。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (966, 'vuj8XAePvKYuPSUnY7ZA5a', 2, '锅中加水烧开，放入少许盐和几滴食用油，将切好的油麦菜焯水1-2分钟，捞出后立即过冷水，沥干水分备用。

💡 提示：焯水时间不宜过长，以免影响口感；过冷水可以保持油麦菜的翠绿色泽。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (967, 'vuj8XAePvKYuPSUnY7ZA5a', 3, '将蒜拍碎切末，与醋、酱油、芝麻酱、香油、糖、蚝油一起放入碗中，搅拌均匀成调味汁。

💡 提示：调味汁要充分搅拌均匀，确保味道融合。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (968, 'vuj8XAePvKYuPSUnY7ZA5a', 4, '将调好的调味汁倒入沥干水分的油麦菜中，用手或筷子充分拌匀，使每一片油麦菜都裹上调味汁。

💡 提示：拌匀时动作要轻柔，避免破坏油麦菜的完整性。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (969, 'FkHOnL4OdCKV88gxgXy3Q2', 1, '将豆腐切成2 cm见方的小块。

💡 提示：选用北豆腐或老豆腐，质地硬不易碎。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 2, '锅中加入500 ml饮用水，大火烧开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (971, 'FkHOnL4OdCKV88gxgXy3Q2', 3, '放入豆腐块，煮1-2分钟以去除豆腥味并使口感更紧实。

💡 提示：焯水后可过凉水提升口感，原文未说明但属常见操作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (972, 'FkHOnL4OdCKV88gxgXy3Q2', 4, '将煮好的豆腐块捞出，沥干水分，放入碗中备用。

💡 提示：务必沥干，避免稀释酱汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 5, '小葱洗净，切成葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 6, '大蒜去皮，切成蒜末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 7, '在小碗中加入生抽15 ml、香油5 ml、醋5 ml（可选）、白糖2 g（可选）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 8, '加入切好的蒜末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 9, '搅拌均匀，使白糖充分溶解，酱汁混合均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 10, '将酱汁均匀淋在豆腐块上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 11, '撒上葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('FkHOnL4OdCKV88gxgXy3Q2', 12, '根据个人喜好淋上辣椒油5 ml（可选）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (981, 'FkHOnL4OdCKV88gxgXy3Q2', 13, '用筷子或勺子轻轻拌匀，即可食用。

💡 提示：轻拌防豆腐碎裂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 1, '切除金针菇根部，用清水冲洗干净。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 2, '小葱洗净，切成葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 3, '大蒜去皮，切成蒜末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 4, '锅中加入1000 ml饮用水，大火烧开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (986, 'MF6st5bxjLXOrw0raUj397', 5, '放入金针菇，煮1–2分钟至变软。

💡 提示：焯水时间不宜过长，以免影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 6, '捞出金针菇，沥干水分，放入大碗中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 7, '在小碗中加入生抽、醋、白糖（可选）、香油（可选）。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 8, '加入切好的蒜末。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 9, '搅拌均匀，使白糖充分溶解，酱汁混合均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 10, '将酱汁均匀淋在金针菇上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 11, '撒上葱花。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (993, 'MF6st5bxjLXOrw0raUj397', 12, '根据个人喜好淋上辣椒油（可选）。

💡 提示：如不喜欢吃辣，可省略', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('MF6st5bxjLXOrw0raUj397', 13, '用筷子轻轻拌匀，即可食用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (995, '5zNRuuLigSxLl4UbgTjFR4', 1, '将黄瓜洗净，去头尾（如果发现有苦味），然后用刀拍扁，再剁成长约3厘米的碎块。

💡 提示：拍打黄瓜可以使其更入味，切块大小均匀有助于调味均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (996, '5zNRuuLigSxLl4UbgTjFR4', 2, '将处理好的黄瓜放入碗中备用。

💡 提示：确保碗足够大，方便后续加入调料和搅拌。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (997, '5zNRuuLigSxLl4UbgTjFR4', 3, '将蒜瓣拍碎后切成细末。

💡 提示：蒜末越细，味道越容易渗透到黄瓜中。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (998, '5zNRuuLigSxLl4UbgTjFR4', 4, '在装有黄瓜的碗中依次加入醋、酱油、盐、蚝油以及切好的蒜末，充分搅拌均匀后腌制15分钟。

💡 提示：腌制过程中偶尔翻动黄瓜，让其更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (999, '5zNRuuLigSxLl4UbgTjFR4', 5, '最后加入香油，并再次搅拌均匀即可食用。

💡 提示：香油应在最后添加，以保持其特有的香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1000, 'zYRE52sHRyQLmfHTuZQHfL', 1, '将土豆洗净去皮，切成1.5cm见方的小块；茄子洗净，切成同样大小的块；尖椒洗净去籽，切成小块。

💡 提示：切块大小一致，便于均匀烹饪', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1001, 'zYRE52sHRyQLmfHTuZQHfL', 2, '葱切段，姜切末，蒜剁碎备用。

💡 提示：提前准备好调料，方便后续操作', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1002, 'zYRE52sHRyQLmfHTuZQHfL', 3, '锅中加入足够的食用油，烧至6成热（约180℃），放入土豆块，中小火煎炸约3分钟，至表面金黄且熟透，捞出沥油。

💡 提示：注意火候，避免炸糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1003, 'zYRE52sHRyQLmfHTuZQHfL', 4, '锅中留少许底油，放入茄子块，中小火煎炸约1分钟，至表面微黄且略软，捞出沥油。

💡 提示：茄子容易吸油，可适当减少油量', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1004, 'zYRE52sHRyQLmfHTuZQHfL', 5, '锅中留少许底油，放入葱段和姜末炒香，再加入豆瓣酱炒出红油。

💡 提示：炒香调料，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1005, 'zYRE52sHRyQLmfHTuZQHfL', 6, '加入生抽、盐和糖，翻炒均匀。

💡 提示：调味品要快速翻炒均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1006, 'zYRE52sHRyQLmfHTuZQHfL', 7, '将煎好的土豆和茄子回锅，加入尖椒块，大火快速翻炒约1分钟。

💡 提示：保持大火快炒，使食材更加入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1007, 'zYRE52sHRyQLmfHTuZQHfL', 8, '将淀粉与少量水调匀成水淀粉，倒入锅中，快速翻炒均匀，待汤汁变稠即可关火。

💡 提示：水淀粉要均匀撒入，防止结块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1008, 'zYRE52sHRyQLmfHTuZQHfL', 9, '最后撒上蒜末，翻炒均匀后出锅装盘。

💡 提示：蒜末最后加入，保留香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1009, 'rFsoNckGhu0K7y6i7zMurz', 1, '将胡萝卜切成薄片，青椒切成薄块，洋葱切成丝，蒜切碎备用。

💡 提示：蔬菜切得均匀，烹饪时熟度一致', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1010, 'rFsoNckGhu0K7y6i7zMurz', 2, '将日本豆腐从包装袋中取出，切成约1cm厚的圆柱体。

💡 提示：切豆腐时要轻柔，避免破碎', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1011, 'rFsoNckGhu0K7y6i7zMurz', 3, '将生粉倒入平盘中，轻轻将豆腐两面和周边都裹上一层薄薄的生粉，抖掉多余的粉。

💡 提示：裹粉时不要包裹得太厚，以免影响口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1012, 'rFsoNckGhu0K7y6i7zMurz', 4, '在平底锅中倒入150ml油，油温烧至六成热（约180℃），放入裹好粉的豆腐，中小火煎至两面金黄，每面约2-3分钟。

💡 提示：油温不宜过高，防止外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1013, 'rFsoNckGhu0K7y6i7zMurz', 5, '将煎好的豆腐捞出，放在厨房纸巾上吸去多余油分，备用。

💡 提示：及时吸油，保持外皮酥脆', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1014, 'rFsoNckGhu0K7y6i7zMurz', 6, '在炒锅中倒入10-15ml油，放入蒜末爆香，再加入青椒、胡萝卜、火腿肠、黑木耳和洋葱，大火快速翻炒2-3分钟。

💡 提示：大火快炒，保持蔬菜的脆嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1015, 'rFsoNckGhu0K7y6i7zMurz', 7, '加入蚝油、生抽、盐、鸡精、白砂糖、番茄酱，继续翻炒均匀，使所有食材充分吸收调料。

💡 提示：调味料要均匀分布，确保味道均衡', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1016, 'rFsoNckGhu0K7y6i7zMurz', 8, '最后将煎好的豆腐回锅，轻轻翻炒几下，使豆腐表面均匀裹上调料。

💡 提示：豆腐回锅时间不宜过长，以免外皮变软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1017, 'XnwjLYUfSWFdDcLh2euc5e', 1, '将玉米粒和胡萝卜丁提前焯水1分钟，捞出沥干备用。

💡 提示：焯水可以去除生味，使玉米更加鲜嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1018, 'XnwjLYUfSWFdDcLh2euc5e', 2, '热锅凉油，待油温升至五成热时，放入胡萝卜丁略炒约1分钟。

💡 提示：油温不宜过高，以免胡萝卜焦糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1019, 'XnwjLYUfSWFdDcLh2euc5e', 3, '加入玉米粒翻炒均匀，炒制约2分钟。

💡 提示：保持中火，使玉米粒受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1020, 'XnwjLYUfSWFdDcLh2euc5e', 4, '加入白砂糖和盐，继续翻炒均匀，炒制约1分钟。

💡 提示：糖和盐要均匀撒在玉米上，使其充分吸收调味料。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1021, 'XnwjLYUfSWFdDcLh2euc5e', 5, '混合水与淀粉成水淀粉，倒入锅中快速翻炒，使汤汁略稠，炒制约1分钟。

💡 提示：水淀粉要慢慢倒入，边倒边快速翻炒，防止结块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1022, 'XnwjLYUfSWFdDcLh2euc5e', 6, '加入熟松仁翻炒均匀，炒制约1分钟。

💡 提示：松仁最后加入，以保持其香脆口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1023, 'XnwjLYUfSWFdDcLh2euc5e', 7, '出锅装盘。

💡 提示：趁热食用，口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1024, 'J64GEpYlJMEQ6UfKBJ5N2q', 1, '将叶菜类蔬菜洗净，去掉老叶和根部，切成适口大小。

💡 提示：确保蔬菜清洗干净，去除杂质。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1025, 'J64GEpYlJMEQ6UfKBJ5N2q', 2, '锅中加入150ml清水，大火烧开。

💡 提示：水不需要太多，刚好能覆盖锅底即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1026, 'J64GEpYlJMEQ6UfKBJ5N2q', 3, '水开后，加入3g盐，搅拌均匀。

💡 提示：先放盐可以让蔬菜更入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1027, 'J64GEpYlJMEQ6UfKBJ5N2q', 4, '如果喜欢，可以加入3ml蚝油，搅拌均匀。

💡 提示：蚝油可以增加鲜味，但不是必须的。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1028, 'J64GEpYlJMEQ6UfKBJ5N2q', 5, '加入2ml食用油，搅拌均匀。

💡 提示：油可以使蔬菜更加鲜亮，口感更好。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1029, 'J64GEpYlJMEQ6UfKBJ5N2q', 6, '将切好的蔬菜放入锅中，用铲子快速翻拌几下，使蔬菜均匀受热。

💡 提示：翻拌要快，避免蔬菜煮得太烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1030, 'J64GEpYlJMEQ6UfKBJ5N2q', 7, '盖上锅盖，转中小火焖1分钟。

💡 提示：时间不宜过长，以免蔬菜失去脆嫩口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1031, 'J64GEpYlJMEQ6UfKBJ5N2q', 8, '打开锅盖，检查蔬菜是否熟透，尝一下咸淡，根据需要调整盐量。

💡 提示：蔬菜应保持翠绿色，口感脆嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1032, 'J64GEpYlJMEQ6UfKBJ5N2q', 9, '将焖好的蔬菜盛出，装盘即可。

💡 提示：尽快食用，以保持最佳口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1033, 'PsQLmSvGXyaPBn5MBZevMU', 1, '将鸡蛋打入碗中备用，不要打散。

💡 提示：鸡蛋保持完整，更容易形成大块', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1034, 'PsQLmSvGXyaPBn5MBZevMU', 2, '小葱切成3cm长的小段，蒜瓣和小米辣放入打蒜器，打成沫。

💡 提示：蒜和小米辣打成沫更易出味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1035, 'PsQLmSvGXyaPBn5MBZevMU', 3, '将香醋、生抽、蚝油、白糖和水加入小碗中，搅拌均匀作为糖醋料汁。

💡 提示：料汁提前调好，方便后续操作', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1036, 'PsQLmSvGXyaPBn5MBZevMU', 4, '锅中倒入35-50mL食用油，油温至七成热时，倒入鸡蛋。

💡 提示：油温七成热时，筷子插入油中有明显气泡即可', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1037, 'PsQLmSvGXyaPBn5MBZevMU', 5, '待鸡蛋凝固后，用铲子将其铲成大块，然后倒入蒜沫、小米辣沫，翻炒均匀。

💡 提示：鸡蛋凝固后再铲成大块，口感更好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1038, 'PsQLmSvGXyaPBn5MBZevMU', 6, '倒入调好的糖醋料汁，大火收汁，约2-3分钟。

💡 提示：大火收汁可以使料汁更好地包裹在鸡蛋上', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1039, 'PsQLmSvGXyaPBn5MBZevMU', 7, '快出锅时加入葱段，翻炒均匀即可出锅。

💡 提示：葱段最后加入，保持脆嫩口感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1040, 'BYCECsLilRLvkP2EIMgbjF', 1, '将花菜洗净，用刀或手掰成小朵，粗茎部分可以切片，备用。

💡 提示：花菜要尽量保持完整的小朵，不要切得太碎', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1041, 'BYCECsLilRLvkP2EIMgbjF', 2, '将大蒜去皮，切成蒜片，备用。

💡 提示：蒜片切得薄一些，更容易出香味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1042, 'BYCECsLilRLvkP2EIMgbjF', 3, '锅中加入1000ml饮用水，大火烧开。

💡 提示：水要足够多，确保花菜能完全浸没', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1043, 'BYCECsLilRLvkP2EIMgbjF', 4, '放入花菜朵，煮2-3分钟，至花菜颜色变浅，口感稍微软化。

💡 提示：焯水时间不宜过长，以免花菜过于软烂', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1044, 'BYCECsLilRLvkP2EIMgbjF', 5, '将煮好的花菜捞出，沥干水分，备用。

💡 提示：可以用漏勺捞出，沥干水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1045, 'BYCECsLilRLvkP2EIMgbjF', 6, '热锅，加入15ml食用油，大火烧热。

💡 提示：油温要高，这样炒出来的花菜更香', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1046, 'BYCECsLilRLvkP2EIMgbjF', 7, '放入蒜片，快速煸炒出香味。

💡 提示：蒜片炒至微黄即可，不要炒糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1047, 'BYCECsLilRLvkP2EIMgbjF', 8, '放入焯好水的花菜朵，转中大火，快速翻炒约2分钟，使花菜均匀受热。

💡 提示：翻炒时要快，确保花菜均匀受热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1048, 'BYCECsLilRLvkP2EIMgbjF', 9, '加入3g盐，继续翻炒均匀。

💡 提示：盐要均匀撒在花菜上，翻炒均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1049, 'BYCECsLilRLvkP2EIMgbjF', 10, '沿锅边淋入50ml饮用水，盖上锅盖，焖1分钟，帮助花菜完全熟透入味。

💡 提示：加少量水焖一下可以使花菜更加鲜嫩', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1050, 'BYCECsLilRLvkP2EIMgbjF', 11, '开盖，快速翻炒均匀，即可出锅。

💡 提示：最后翻炒几下，确保调味均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1051, '3VZerxG69xB8MKYrVfnjWO', 1, '将南瓜外皮洗净，去除瓜瓤和籽。

💡 提示：确保南瓜表面干净，去除瓜瓤和籽时要彻底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1052, '3VZerxG69xB8MKYrVfnjWO', 2, '将南瓜切成厚度大约2cm的片，备用。

💡 提示：切片厚度均匀可以使南瓜受热均匀，蒸制时间一致。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1053, '3VZerxG69xB8MKYrVfnjWO', 3, '在蒸锅中加入1000ml饮用水，并将蒸架放入蒸锅中。

💡 提示：确保蒸架稳固，避免蒸制过程中晃动。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1054, '3VZerxG69xB8MKYrVfnjWO', 4, '将切好的南瓜片均匀摆放在盘中。

💡 提示：尽量不要重叠摆放，以便蒸汽能够均匀加热每一片南瓜。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1055, '3VZerxG69xB8MKYrVfnjWO', 5, '待蒸锅中的水烧开后（约5-7分钟），将装有南瓜的盘子放入蒸锅中。

💡 提示：水烧开后再放入南瓜，可以保证南瓜快速受热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1056, '3VZerxG69xB8MKYrVfnjWO', 6, '盖上锅盖，保持大火蒸15-20分钟，直至南瓜变软，可以用筷子轻松穿透。

💡 提示：用筷子测试是判断是否蒸熟的好方法。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1057, '3VZerxG69xB8MKYrVfnjWO', 7, '关火，小心取出盘子。

💡 提示：取出盘子时注意防烫，可以使用隔热手套。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1058, 'QXSlDZHAgvqEEBBAsp6nRr', 1, '将茄子洗净，竖切成两段，再切成菱形块，放入碗中待用。

💡 提示：切好的茄子可以撒少许盐腌制一下，去除多余水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1059, 'QXSlDZHAgvqEEBBAsp6nRr', 2, '将香葱洗净，切成葱花，放在案板上备用。

💡 提示：葱花可以分两次加入，一次在炒料时，一次在出锅前', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1060, 'QXSlDZHAgvqEEBBAsp6nRr', 3, '如果使用肉末，先用10ml油中火炒至变色（约1分钟），然后盛出备用。

💡 提示：炒肉末时可以加少许料酒去腥', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1061, 'QXSlDZHAgvqEEBBAsp6nRr', 4, '开火热锅，直至锅内没有水。

💡 提示：确保锅热后再加油，防止粘锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1062, 'QXSlDZHAgvqEEBBAsp6nRr', 5, '往锅内倒食用油，油量没过锅底的两倍。热油至6成热（约170℃），放入八角、虾皮、香葱这三种可选性材料。

💡 提示：可以用筷子插入油中，周围有小气泡即可判断为6成热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1063, 'QXSlDZHAgvqEEBBAsp6nRr', 6, '如果没有八角等可选材料，热油至9成热（约200℃）。待锅内的油到9成热，将碗中的茄子倒入锅内用锅铲进行翻炒。

💡 提示：油温高可以使茄子快速熟透，减少吸油', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1064, 'QXSlDZHAgvqEEBBAsp6nRr', 7, '翻炒约40秒后，将锅铲悬空，与锅平行，把酱油倒入锅铲内，均匀淋在茄子上。

💡 提示：酱油不要直接倒在茄子上，以免局部过咸', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1065, 'QXSlDZHAgvqEEBBAsp6nRr', 8, '继续翻炒约1分钟后，放回预炒的肉末，快速搅拌均匀。

💡 提示：肉末和茄子要充分混合，使味道更均匀', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1066, 'QXSlDZHAgvqEEBBAsp6nRr', 9, '如果打算加入糖和醋，此时加入糖和醋，继续翻炒。

💡 提示：糖和醋要在最后阶段加入，避免过早挥发', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1067, 'QXSlDZHAgvqEEBBAsp6nRr', 10, '等到锅内所有茄子变色且变软时捞出，装盘即可。

💡 提示：出锅前尝一下味道，如果不咸可以加微量的盐', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1068, '8Q0Hzc2HKnAwzxXKuyhgil', 1, '将上海青掰成小瓣，用清水洗净，沥干水分备用。

💡 提示：确保青菜彻底洗净，去除泥沙', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1069, '8Q0Hzc2HKnAwzxXKuyhgil', 2, '中火预热锅，加入10-15ml食用油，等待30秒让油温升高。

💡 提示：油温不宜过高，以免青菜下锅后立即焦糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1070, '8Q0Hzc2HKnAwzxXKuyhgil', 3, '将准备好的青菜倒入锅中，快速翻炒至青菜变软（约1分钟）。

💡 提示：保持大火快炒，使青菜均匀受热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1071, '8Q0Hzc2HKnAwzxXKuyhgil', 4, '加入2g食盐，继续翻炒均匀（约30秒）。

💡 提示：盐要均匀撒在青菜上，避免局部过咸', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1072, '8Q0Hzc2HKnAwzxXKuyhgil', 5, '最后加入5g白糖，快速翻炒均匀（约30秒），即可出锅。

💡 提示：白糖可以提鲜并使青菜颜色更绿', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1073, 'QTEj8k2l6RF9YlyYrav9g1', 1, '将内酯豆腐从盒子中取出，切成厚片或块状，放入盘中。

💡 提示：切豆腐时要轻柔，以免破坏豆腐的形状。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1074, 'QTEj8k2l6RF9YlyYrav9g1', 2, '将皮蛋剥壳，切成四瓣，放在豆腐旁边。

💡 提示：切皮蛋前可以在刀上抹一点香油，防止粘刀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1075, 'QTEj8k2l6RF9YlyYrav9g1', 3, '在一个小碗中，将生抽、白砂糖、镇江香醋、香油和辣椒油混合均匀，调成酱汁。

💡 提示：可以根据个人口味调整调料的比例。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1076, 'QTEj8k2l6RF9YlyYrav9g1', 4, '将调好的酱汁均匀地淋在皮蛋和豆腐上。

💡 提示：确保每一块豆腐和皮蛋都能沾到酱汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1077, 'QTEj8k2l6RF9YlyYrav9g1', 5, '最后撒上花生碎、葱花和香菜即可。

💡 提示：这些配料可以增加菜品的口感和香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1078, '9PQfogADNvSUfUrja9aC3l', 1, '将葱切成葱花，蒜切成末，备用。

💡 提示：切好的葱花和蒜末分开存放，以免混淆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1079, '9PQfogADNvSUfUrja9aC3l', 2, '将生抽、老抽、蚝油和盐混合成调料汁，备用。

💡 提示：调料汁提前准备好，方便后续操作。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1080, '9PQfogADNvSUfUrja9aC3l', 3, '将小米椒切成圈，备用。

💡 提示：小米椒可根据个人口味调整用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1081, '9PQfogADNvSUfUrja9aC3l', 4, '将豆角去筋，斜切成4-10cm的小段，备用。

💡 提示：斜切可以使豆角更容易入味，如果刀工不好，可以使用剪刀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1082, '9PQfogADNvSUfUrja9aC3l', 5, '起锅烧油（约15ml），待油温升至冒烟后放入葱花和小米椒，翻炒至闻到香味。

💡 提示：油温要高，这样能更好地激发出葱花和小米椒的香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1083, '9PQfogADNvSUfUrja9aC3l', 6, '加入豆角，大火翻炒约1分钟，直到豆角变色且断生。

💡 提示：豆角需要炒至表面略微焦黄，这样口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1084, '9PQfogADNvSUfUrja9aC3l', 7, '加入调好的料汁，继续大火翻炒2分钟，使豆角均匀裹上酱汁。

💡 提示：快速翻炒，确保豆角均匀受热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1085, '9PQfogADNvSUfUrja9aC3l', 8, '倒入150ml水，水量应没过豆角的一半。

💡 提示：水量不要太多，以免豆角过于软烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1086, '9PQfogADNvSUfUrja9aC3l', 9, '转中小火，盖上锅盖焖制8-10分钟，直至豆角熟透。

💡 提示：期间可适当开盖检查豆角的熟度，避免过度焖煮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1087, '9PQfogADNvSUfUrja9aC3l', 10, '最后加入蒜末，翻炒均匀后即可出锅。

💡 提示：蒜末在最后加入，可以保留其香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1088, 'NLK3nj5wczSUsB3N9KCNe3', 1, '将青茄子洗净，去蒂，切成2厘米厚的片，再切成2厘米宽的条，最后斜刀切成菱形块。切好的茄子放入碗中，撒上适量的盐，腌制10分钟，然后挤去多余的水分。

💡 提示：茄子切好后用盐腌制可以去除多余的水分，使炸出来的茄子更加酥脆。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1089, 'NLK3nj5wczSUsB3N9KCNe3', 2, '将青辣椒、洋葱、西红柿、大葱分别洗净，切成小块。大蒜剥皮并拍碎备用。

💡 提示：蔬菜切块要均匀，这样烹饪时受热更均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1090, 'NLK3nj5wczSUsB3N9KCNe3', 3, '在一个大碗中加入面粉，慢慢加入少量水，搅拌成粘稠糊状。然后加入淀粉和30克水，继续搅拌均匀。打入一个鸡蛋，加入适量的盐，再次搅拌均匀。

💡 提示：面糊的浓稠度要适中，太稀或太稠都会影响炸制效果。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1091, 'NLK3nj5wczSUsB3N9KCNe3', 4, '将腌制好的茄子块倒入面糊中，搅拌均匀，使每一块茄子都裹上面糊。

💡 提示：确保每一块茄子都均匀裹上面糊，这样炸出来的茄子才会外酥里嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1092, 'NLK3nj5wczSUsB3N9KCNe3', 5, '锅中倒入500毫升食用油，开大火加热至油温达到180℃左右（可以用筷子试油温，筷子周围冒小泡即可）。转小火，将裹好面糊的茄子块逐个夹入油锅中，待所有茄子块下锅后，调至中火，炸至金黄色捞出，沥干油分。

💡 提示：炸茄子时要控制好油温，太高容易炸糊，太低则会吸油过多。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1093, 'NLK3nj5wczSUsB3N9KCNe3', 6, '锅中留少许底油，加入拍碎的大蒜和切好的葱花，翻炒15秒，再加入青辣椒块翻炒30秒，接着加入西红柿块翻炒30秒。

💡 提示：炒香调料后再加入其他食材，可以使菜肴更加美味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1094, 'NLK3nj5wczSUsB3N9KCNe3', 7, '将炸好的茄子块倒入锅中，加入适量的水（水面高度约为锅内食材的0.8倍），加入酱油和适量的盐调味。

💡 提示：加水量要适中，太多会使菜肴过于稀薄，太少则会影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1095, 'NLK3nj5wczSUsB3N9KCNe3', 8, '盖上锅盖，中小火炖煮10分钟左右，直到汤汁变得粘稠，打开锅盖，翻炒均匀，盛出装盘。

💡 提示：炖煮过程中要注意观察汤汁的浓稠度，适时调整火力。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1096, 'p2oHri6YesXLSMFMK7VVt3', 1, '将鸡蛋打入碗中，搅拌均匀形成蛋液，放置备用。

💡 提示：确保蛋液充分打散，无明显蛋白块。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1097, 'p2oHri6YesXLSMFMK7VVt3', 2, '在一个小碗中配置酱料：加入20g生抽、10g蚝油、5g老抽、10g白糖、10g玉米淀粉和200ml清水，搅拌均匀。

💡 提示：确保所有调料充分混合，无颗粒状物。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1098, 'p2oHri6YesXLSMFMK7VVt3', 3, '将老豆腐切成约1.2cm厚的片，每块豆腐可切5-6片。

💡 提示：切片时尽量保持厚度一致，以便均匀受热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1099, 'p2oHri6YesXLSMFMK7VVt3', 4, '将切好的豆腐片先在玉米淀粉中裹一层，再蘸上蛋液，放置一旁备用。

💡 提示：确保每一片豆腐都均匀裹上淀粉和蛋液，避免粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1100, 'p2oHri6YesXLSMFMK7VVt3', 5, '平底锅预热后，倒入18ml食用油，等待油温升至约160°C（约10秒），放入裹好蛋液的豆腐片。

💡 提示：可以用筷子试油温，周围有细小气泡即可。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1101, 'p2oHri6YesXLSMFMK7VVt3', 6, '小火煎至两面金黄，每面约3-4分钟。

💡 提示：注意翻面时要轻柔，以免破坏豆腐形状。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1102, 'p2oHri6YesXLSMFMK7VVt3', 7, '待两面煎至金黄后，倒入调好的酱料，让每块豆腐都沐浴在酱料中，大火煮3分钟至酱汁浓稠。

💡 提示：期间可以轻轻晃动锅子，使豆腐均匀裹上酱汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1103, 'p2oHri6YesXLSMFMK7VVt3', 8, '关火，将豆腐盛出装盘，静置1-2分钟后即可享用。

💡 提示：静置片刻可以让豆腐更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1104, 'oFumXoZEzsGq3lsaO7617m', 1, '将茄子、土豆、青辣椒洗净。茄子和土豆切成约6立方厘米的块，青辣椒切成小块，猪肉切成3厘米的丝，蒜拍碎备用。

💡 提示：切块大小均匀，便于烹饪时熟透一致', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1105, 'oFumXoZEzsGq3lsaO7617m', 2, '热锅后加入13毫升食用油，待油温升至六成热（约180℃），放入青辣椒煸炒出香味。

💡 提示：油温不宜过高，以免辣椒焦糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1106, 'oFumXoZEzsGq3lsaO7617m', 3, '放入猪肉丝，用铲子翻炒30秒，使肉丝变色。

💡 提示：快速翻炒，避免肉丝粘锅', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1107, 'oFumXoZEzsGq3lsaO7617m', 4, '加入土豆块，继续翻炒30秒。

💡 提示：土豆块要均匀受热', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1108, 'oFumXoZEzsGq3lsaO7617m', 5, '加入茄子块，翻炒30秒。如果锅底没有液体，可加5毫升水再继续翻炒。

💡 提示：茄子容易吸油，注意控制火候', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1109, 'oFumXoZEzsGq3lsaO7617m', 6, '加入15毫升酱油和5克盐，继续翻炒5分钟，使食材充分吸收调料。

💡 提示：翻炒均匀，让每一块食材都裹上调料', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1110, 'oFumXoZEzsGq3lsaO7617m', 7, '加入足够的水，水面高度约为食材高度的90%，盖上锅盖，转中小火炖煮20分钟。

💡 提示：保持中小火，防止水分蒸发过快', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1111, 'oFumXoZEzsGq3lsaO7617m', 8, '当锅内水的高度剩余食材高度的10%时，开盖，放入拍碎的蒜，搅拌均匀，关火。

💡 提示：蒜末最后加入，保留其香气', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1112, 'hHvrACv7iA4YEVhD7PGqfD', 1, '将豆腐洗净，切成约5毫米厚的片，放在盘子里备用。

💡 提示：切豆腐时要小心，尽量保持厚度均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1113, 'hHvrACv7iA4YEVhD7PGqfD', 2, '将葱洗净，去掉根部，切成葱花；青辣椒洗净，去籽，切成1厘米见方的小块，备用。

💡 提示：切葱花时可以稍微切细一些，这样更易出香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1114, 'hHvrACv7iA4YEVhD7PGqfD', 3, '热锅后加入约30毫升食用油，待油温升至五成热时，放入豆腐片，小火慢煎。

💡 提示：煎豆腐时不要急于翻动，等底部金黄后再翻面。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1115, 'hHvrACv7iA4YEVhD7PGqfD', 4, '将两面煎至金黄色的豆腐盛出，放在盘子里备用。

💡 提示：可以用厨房纸巾吸去多余的油分。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1116, 'hHvrACv7iA4YEVhD7PGqfD', 5, '在锅中补加约20毫升食用油，倒入青辣椒大火快速翻炒，并用铲子轻轻碾压辣椒，持续3分钟。

💡 提示：碾压辣椒可以让其更好地释放香气。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1117, 'hHvrACv7iA4YEVhD7PGqfD', 6, '将煎好的豆腐重新倒回锅中，加入盐和鸡精，中火翻炒均匀，然后加入10毫升水，大火收汁。

💡 提示：收汁时注意观察，避免烧焦。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1118, 'hHvrACv7iA4YEVhD7PGqfD', 7, '最后撒上之前准备好的葱花，迅速翻炒几下即可出锅装盘。

💡 提示：葱花要在最后撒入，以保持其鲜绿色泽和香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1119, 'sSlc7zyvdG4EHoekajA9Pr', 1, '将西兰花切成小朵，用清水彻底清洗干净。

💡 提示：可加少许盐浸泡2分钟去农残', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 2, '将大蒜去皮，切成细蒜末，备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 3, '锅中加入1000 ml饮用水，大火烧开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1122, 'sSlc7zyvdG4EHoekajA9Pr', 4, '水沸后放入西兰花，保持大火焯水2-3分钟，至颜色转翠绿、口感变软（但仍带脆感）。

💡 提示：焯水时间不宜超过3分钟，以免营养流失和过软', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1123, 'sSlc7zyvdG4EHoekajA9Pr', 5, '将焯好的西兰花捞出，沥干水分，整齐摆入盘中。

💡 提示：可用厨房纸轻吸表面水汽，便于后续挂汁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1124, 'sSlc7zyvdG4EHoekajA9Pr', 6, '热锅倒入10 ml食用油，油温升至约120℃（微冒青烟前），转小火，下蒜末煸炒。

💡 提示：需小火防焦，至蒜香逸出、边缘微黄', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 7, '加入10 ml生抽、5 ml蚝油、2 g白糖，翻炒均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1126, 'sSlc7zyvdG4EHoekajA9Pr', 8, '加入30 ml饮用水，将锅中汤汁烧开。

💡 提示：烧至沸腾即可，无需收浓', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('sSlc7zyvdG4EHoekajA9Pr', 9, '将烧好的蒜蓉汁均匀淋在盘中的西兰花上。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1128, 'hcxK9liQGBqv7sv4QlNiwX', 1, '将茄子洗净，削去外皮，然后横切成两段。

💡 提示：削皮时注意不要削得太厚，以免浪费。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1129, 'hcxK9liQGBqv7sv4QlNiwX', 2, '将切好的茄子放入蒸锅中，大火蒸5分钟。

💡 提示：蒸的时间不宜过长，以免茄子过于软烂。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1130, 'hcxK9liQGBqv7sv4QlNiwX', 3, '取出蒸好的茄子，纵向切开但不要切断，在两边切面各划2-3刀，使其能够摊平。

💡 提示：切口要均匀，以便更好地吸收酱汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1131, 'hcxK9liQGBqv7sv4QlNiwX', 4, '在不粘锅或铁锅中加入适量的油，油热后放入茄子，小火煎至两面金黄。

💡 提示：煎的时候要用小火，防止外焦里生。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1132, 'hcxK9liQGBqv7sv4QlNiwX', 5, '将蒲烧汁、蜂蜜、白糖、生抽、老抽、料酒和水混合均匀，倒入锅中，使酱汁没过茄子的一半高度。

💡 提示：酱汁的比例可以根据个人口味进行微调。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1133, 'hcxK9liQGBqv7sv4QlNiwX', 6, '继续用中小火煎煮，期间翻动茄子，使其均匀上色并吸收酱汁。

💡 提示：翻动时要小心，避免茄子散开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1134, 'hcxK9liQGBqv7sv4QlNiwX', 7, '当酱汁浓稠时，如果觉得不够浓稠，可以加入适量的水淀粉（生粉和水的比例为1:4到1:10），收汁至理想的浓稠度。

💡 提示：收汁时要不断搅拌，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1135, 'hcxK9liQGBqv7sv4QlNiwX', 8, '将剩下的蒲烧汁浇在茄子上，出锅装盘。

💡 提示：装盘时可以撒上一些葱花，增加色彩和香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1136, 'gsTdq9ggWql86xJyPRYO3U', 1, '将生菜洗净并去掉烂菜叶，沥干水分备用。

💡 提示：确保生菜叶片干净无杂质', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1137, 'gsTdq9ggWql86xJyPRYO3U', 2, '热锅，加入约500ml清水，放入2ml-3ml食用油和0.5g盐，等待锅中的水煮沸。

💡 提示：加少量油和盐可以使生菜颜色更鲜亮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1138, 'gsTdq9ggWql86xJyPRYO3U', 3, '水沸后，放入生菜，每一片生菜叶焯水10秒。

💡 提示：焯水时间不宜过长，以免生菜失去脆感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1139, 'gsTdq9ggWql86xJyPRYO3U', 4, '捞出生菜，控干水分，摆盘。

💡 提示：可以用厨房纸巾吸去多余的水分', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1140, 'gsTdq9ggWql86xJyPRYO3U', 5, '调汁：将6ml生抽、6-8ml蚝油、0.5g盐、1g白糖放入碗中调匀，并加入10-15ml凉开水搅拌均匀。

💡 提示：调汁时可以尝一下味道，根据个人口味调整', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1141, 'gsTdq9ggWql86xJyPRYO3U', 6, '另起一锅，热锅后放入5-8ml食用油，油热后放入蒜泥。

💡 提示：油温不要过高，以免蒜末焦糊', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1142, 'gsTdq9ggWql86xJyPRYO3U', 7, '待蒜香飘出，倒入调好的汁，煮沸即可，立马关火。

💡 提示：煮沸后立即关火，保持酱汁的鲜美', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1143, 'gsTdq9ggWql86xJyPRYO3U', 8, '将锅中的汤汁均匀地浇在生菜上，即可上桌。

💡 提示：浇汁时尽量让每片生菜都沾到酱汁', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1144, 'u8R1sdJuG0pywQCFFVDmZk', 1, '将西红柿洗净，用开水烫表皮后放入冷水中，剥去外皮。

💡 提示：烫皮可以使西红柿更容易去皮，且不影响口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1145, 'u8R1sdJuG0pywQCFFVDmZk', 2, '去掉西红柿的蒂部，切成边长不超过4cm的小块。

💡 提示：切块大小均匀，便于烹饪时受热均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1146, 'u8R1sdJuG0pywQCFFVDmZk', 3, '将鸡蛋打入碗中，加入3g盐，搅匀成鸡蛋液。可以考虑向鸡蛋中加入1ml醋，去除腥味并使鸡蛋更蓬松。

💡 提示：打蛋时尽量打散，使蛋液更加细腻。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1147, 'u8R1sdJuG0pywQCFFVDmZk', 4, '热锅，加入12ml食用油，待油温升至五成热时倒入鸡蛋液。

💡 提示：油温不宜过高，以免鸡蛋煎糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1148, 'u8R1sdJuG0pywQCFFVDmZk', 5, '翻炒鸡蛋液，直至鸡蛋结为固体且颜色微微发黄，关火，将半熟鸡蛋盛出备用。

💡 提示：鸡蛋不要炒得太老，保持嫩滑口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1149, 'u8R1sdJuG0pywQCFFVDmZk', 6, '锅中留底油，重新开火，加入西红柿块，用锅铲拍打并翻炒20秒，或至西红柿软烂。

💡 提示：拍打西红柿有助于释放更多汁水，增加菜肴的汤汁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1150, 'u8R1sdJuG0pywQCFFVDmZk', 7, '将半熟鸡蛋倒回锅中，与西红柿一起翻炒均匀。

💡 提示：快速翻炒，使鸡蛋和西红柿充分融合。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1151, 'u8R1sdJuG0pywQCFFVDmZk', 8, '根据个人口味，可以加入10ml番茄酱和50ml清水，增加汤汁。

💡 提示：加水和番茄酱可以使菜肴更加浓郁。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1152, 'u8R1sdJuG0pywQCFFVDmZk', 9, '加入剩余的盐、糖（如果喜欢甜味版本）、葱花，翻炒均匀。

💡 提示：调味品要最后加入，以免影响食材的原味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1153, 'u8R1sdJuG0pywQCFFVDmZk', 10, '关火，将炒好的西红柿炒鸡蛋盛盘即可。

💡 提示：趁热食用，味道更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1154, 'gftRjjHVkwMyaeQzQYe2ah', 1, '将土豆去皮，切成细丝（或使用刨丝器）。

💡 提示：切好的土豆丝要尽量均匀，这样烹饪时受热更均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1155, 'gftRjjHVkwMyaeQzQYe2ah', 2, '将切好的土豆丝放入清水中浸泡，去除多余的淀粉，然后捞出沥干水分。

💡 提示：清洗土豆丝时多换几次水，确保淀粉完全去除，避免炒制时粘连。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1156, 'gftRjjHVkwMyaeQzQYe2ah', 3, '将土豆丝放入沸水中焯水10秒，捞出后迅速过凉水，沥干备用。

💡 提示：焯水时间不宜过长，以免土豆丝变软失去脆感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1157, 'gftRjjHVkwMyaeQzQYe2ah', 4, '将大蒜切末，青椒和红椒切丝，干辣椒剪成小段，葱切段备用。

💡 提示：所有配料提前准备好，方便后续快速翻炒。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1158, 'gftRjjHVkwMyaeQzQYe2ah', 5, '热锅冷油，加入食用油，小火加热至油温五成热，下入蒜末和干辣椒爆香。

💡 提示：注意火候，防止蒜末和干辣椒炸糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1159, 'gftRjjHVkwMyaeQzQYe2ah', 6, '加入青椒丝和红椒丝，翻炒几下，再加入土豆丝，大火快速翻炒至土豆丝变色。

💡 提示：大火快炒可以保持土豆丝的脆爽口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1160, 'gftRjjHVkwMyaeQzQYe2ah', 7, '加入生抽、陈醋，继续翻炒均匀，最后加入盐调味，快速翻炒均匀即可出锅。

💡 提示：调味品加入后要快速翻炒均匀，避免炒糊。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1161, 'JWSsXj9TxfpReLRg573Om3', 1, '将日本豆腐切成厚约1cm的片，小火煎至两面金黄，出锅备用。

💡 提示：煎豆腐时火候要小，防止外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1162, 'JWSsXj9TxfpReLRg573Om3', 2, '将蒜切末；将生抽、蚝油、老抽、糖和100ml水混合均匀，调成料汁备用。

💡 提示：料汁提前调好，方便后续操作', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1163, 'JWSsXj9TxfpReLRg573Om3', 3, '热锅放油，油热后放入小米椒和蒜末爆香，再放入金针菇翻炒至软。

💡 提示：金针菇一定要先炒软，这样更易入味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1164, 'JWSsXj9TxfpReLRg573Om3', 4, '将煎好的豆腐平铺在金针菇上，倒入步骤2中调好的料汁，盖上锅盖，中小火焖煮5分钟。

💡 提示：豆腐尽量不要翻炒，以免破碎', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1165, 'JWSsXj9TxfpReLRg573Om3', 5, '开大火收汁，待汤汁浓稠即可出锅。

💡 提示：收汁时注意观察，避免糊底', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1166, 'E7mIfYYbAH3SRqLYv6i1ZM', 1, '将鸡蛋放入锅中，加入足够的冷水，大火煮开后转小火煮8分钟。

💡 提示：确保鸡蛋完全煮熟，便于剥皮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1167, 'E7mIfYYbAH3SRqLYv6i1ZM', 2, '煮好的鸡蛋捞出，用自来水冲凉，方便剥皮。

💡 提示：冷水冲凉有助于快速降温，便于剥皮', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1168, 'E7mIfYYbAH3SRqLYv6i1ZM', 3, '将蒜切末（粒径不大于1mm），线椒和小米辣切小粒（约2-3mm）。

💡 提示：切得越细，口感越好', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1169, 'E7mIfYYbAH3SRqLYv6i1ZM', 4, '每个熟鸡蛋沿短轴切成体积类似的4份。

💡 提示：切片要均匀，便于煎制', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1170, 'E7mIfYYbAH3SRqLYv6i1ZM', 5, '如果打算沾淀粉，每片鸡蛋粘上淀粉，抖掉多余的淀粉。

💡 提示：淀粉可以增加蛋片的脆感', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1171, 'E7mIfYYbAH3SRqLYv6i1ZM', 6, '锅内放入25ml油（如果不沾淀粉，放20ml），放入熟鸡蛋片，中火煎至微焦黄。

💡 提示：中火煎制，防止外焦里生', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1172, 'E7mIfYYbAH3SRqLYv6i1ZM', 7, '补10ml油（如果不沾淀粉，补10ml），翻面继续煎至另一面微黄。

💡 提示：翻面时要轻柔，防止蛋片散开', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1173, 'E7mIfYYbAH3SRqLYv6i1ZM', 8, '加入线椒、小米辣、蒜末，煎制约1分钟，翻面。

💡 提示：辣椒和蒜末要均匀分布在蛋片上', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1174, 'E7mIfYYbAH3SRqLYv6i1ZM', 9, '接着加豆豉，煎制约30秒，翻面。

💡 提示：豆豉要均匀分布在蛋片上，增加风味', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1175, 'E7mIfYYbAH3SRqLYv6i1ZM', 10, '将生抽、蚝油、糖调成汁，倒入锅中，轻轻颠锅使调料均匀分布，再煎约1分钟后即可出锅。

💡 提示：轻轻颠锅可以使调料均匀分布，避免过度翻炒导致蛋片散开', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1176, 'ZEpMDvpb2zhvvPVAliXbhx', 1, '将葱切成花，姜切成丝，蒜切成末，备用。

💡 提示：切好的葱姜蒜可以提前准备好，避免烹饪时手忙脚乱。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1177, 'ZEpMDvpb2zhvvPVAliXbhx', 2, '豆角去筋，切成2-10cm的小段，备用。

💡 提示：豆角去筋后口感更佳，切段长度可根据个人喜好调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1178, 'ZEpMDvpb2zhvvPVAliXbhx', 3, '土豆去皮，切成1cm³的小块，备用。

💡 提示：土豆切块不宜过大，以免不易煮熟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1179, 'ZEpMDvpb2zhvvPVAliXbhx', 4, '西红柿去皮，切成1cm³的小块，备用。

💡 提示：西红柿去皮后更容易熬出汁水，增加菜肴的风味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1180, 'ZEpMDvpb2zhvvPVAliXbhx', 5, '螺丝椒去籽，切成0.15cm宽的条，备用。

💡 提示：螺丝椒切条后更易入味，且不会过于辣口。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1181, 'ZEpMDvpb2zhvvPVAliXbhx', 6, '起锅烧油（10-15ml），待油温升至冒烟后放入葱姜蒜，翻炒至闻到香味。

💡 提示：油温要足够高，这样葱姜蒜的香味才能充分释放。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1182, 'ZEpMDvpb2zhvvPVAliXbhx', 7, '加入豆角，翻炒至变色（青绿色变为翠绿色），约需3-5分钟。

💡 提示：豆角变色后会更加脆嫩，注意火候不要太大，以免糊锅。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1183, 'ZEpMDvpb2zhvvPVAliXbhx', 8, '加入土豆块，翻炒30秒。

💡 提示：土豆稍微翻炒一下，使其表面略微焦黄，增加口感。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1184, 'ZEpMDvpb2zhvvPVAliXbhx', 9, '加入热水（水面刚刚漫过菜），盖上锅盖，小火熬至土豆变软，约需15-20分钟。

💡 提示：用小火慢慢熬制，可以使土豆更加软糯，同时保持豆角的脆嫩。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1185, 'ZEpMDvpb2zhvvPVAliXbhx', 10, '加入西红柿块，再加入盐、生抽、蚝油、五香粉和辣椒，继续熬至西红柿成汁，约需10-15分钟。

💡 提示：熬制过程中要偶尔翻搅，防止糊底。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1186, 'ZEpMDvpb2zhvvPVAliXbhx', 11, '最后加入香菜碎，翻炒均匀后即可出锅。

💡 提示：香菜碎可以增加菜肴的香气，不喜欢香菜的可以省略。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1187, 'VEv1rkpRIigyCqb8KhbMkc', 1, '将青椒清洗干净，去除根部，侧面切开，去除内部的籽后在案板上压平，备用。

💡 提示：一定要去除青椒籽，否则会在锅里炸开。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1188, 'VEv1rkpRIigyCqb8KhbMkc', 2, '将葱切成半厘米的小段，备用。

💡 提示：使用葱绿部分口感更佳。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1189, 'VEv1rkpRIigyCqb8KhbMkc', 3, '将蒜去皮，切成碎末，备用。

💡 提示：蒜末可以增加菜肴的香味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1190, 'VEv1rkpRIigyCqb8KhbMkc', 4, '将皮蛋去皮，整颗备用。

💡 提示：皮蛋可以提前冷藏，这样更容易去皮。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1191, 'VEv1rkpRIigyCqb8KhbMkc', 5, '将小米辣切成5-10mm的小段，备用。

💡 提示：小米辣可以根据个人口味调整用量。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1192, 'VEv1rkpRIigyCqb8KhbMkc', 6, '热锅，锅内放入10-20ml食用油，放入全部青椒，改小火保持锅子温度，煎至青椒变软（可以用筷子试一下，插入即透即可），大约需要5-7分钟。

💡 提示：小火慢煎可以使青椒更加入味。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1193, 'VEv1rkpRIigyCqb8KhbMkc', 7, '关火，将煎好的青椒和皮蛋放入深一点的小铁盆中。

💡 提示：小铁盆可以帮助更好地混合食材。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1194, 'VEv1rkpRIigyCqb8KhbMkc', 8, '方法1：如果有擀面杖且砸东西不会吵到邻居，可以用擀面杖的一头在小盆中砸击皮蛋和青椒，至皮蛋与青椒混合；方法2：将青椒用手撕成大约半厘米的条状，用叉子将皮蛋压碎。

💡 提示：两种方法都可以使皮蛋和青椒充分混合，方法1更适合追求口感的人，方法2则更为方便。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1195, 'VEv1rkpRIigyCqb8KhbMkc', 9, '加入切好的小米辣，倒入15-20ml生抽，15-20ml陈醋，6-10g白糖，5-7ml香油，以及其他未使用的备用食材（葱段、蒜末），均匀搅拌。

💡 提示：调味料的比例可以根据个人口味进行调整。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 1, '黄瓜洗净，切半圆形片，备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 2, '火腿肠切半圆形片，备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 3, '红尖椒切碎（可选），备用。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 4, '鸡蛋打入碗中，搅匀成鸡蛋液。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 5, '热锅倒入5ml食用油，油热后转小火。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1201, '6L7qXgVM1wHfwzhCkghj9W', 6, '倒入鸡蛋液，用筷子划散，翻炒至鸡蛋凝固、颜色微微发黄（呈半熟状态），盛出备用。

💡 提示：保持小火避免炒老', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 7, '不洗锅，再倒入5ml食用油，大火烧热。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 8, '倒入黄瓜片，大火翻炒1分钟。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step (recipe_id, step, description, created_at, updated_at) VALUES ('6L7qXgVM1wHfwzhCkghj9W', 9, '将半熟鸡蛋倒回锅中，加入盐和生抽，快速翻炒均匀。', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_step VALUES (1205, '6L7qXgVM1wHfwzhCkghj9W', 10, '立即加入火腿片和红尖椒碎（如用），翻炒均匀。

💡 提示：火腿最后加，避免过咸', '2025-12-28 19:17:19', '2025-12-28 19:17:19');

-- ==================== t_tag ====================

INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('air_fryer', '空气炸锅', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('american', '美式', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('beginner', '新手友好', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('beijing', '京菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('bitter', '苦', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('breakfast', '早餐', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('cantonese', '粤菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('chaozhou', '潮州菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('comfort_food', '治愈系', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('cumin', '孜然', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('curry', '咖喱', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('dongbei', '东北菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('elderly_friendly', '适合老人', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('fujian', '闽菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('garlic', '蒜香', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('ginger', '姜香', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('hangover', '解酒', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('high_protein', '高蛋白', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('hunan', '湘菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('italian', '意餐', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('jiangsu', '苏菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('kids_friendly', '适合儿童', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('korean', '韩餐', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('late_night', '夜宵', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('light', '清淡', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('low_fat', '低脂', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('lunch_box', '便当', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('microwave', '微波炉', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('middle_eastern', '中东菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('mild_spicy', '微辣', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('no_cook', '免开火', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('northwest', '西北菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('nourishing', '滋补', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('one_pot', '一锅出', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('party', '聚会宴客', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('picnic', '野餐', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('quick_meal', '快手菜', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('rainy_comfort', '雨天治愈', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('savory', '咸鲜', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('scallion', '葱香', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('sesame', '芝麻香', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('shandong', '鲁菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('shanghai', '本帮菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('sichuan', '川菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('slow_cook', '慢炖', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('smoky', '烟熏', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('sour', '酸', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('spanish', '西班牙菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('spicy', '香辣', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('spring_fresh', '春季尝鲜', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('summer_cool', '夏日清凉', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('sweet', '甜', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('sweet_sour', '酸甜', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('vegetarian', '素食', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('vietnamese', '越南菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('vinegar', '醋香', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('wine', '酒香', 'flavor', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('winter_warm', '冬日暖身', 'scene', '2025-12-28 19:17:19', '2025-12-28 19:17:19');
INSERT INTO t_tag (value, label, type, created_at, updated_at) VALUES ('zhejiang', '浙菜', 'cuisine', '2025-12-28 19:17:19', '2025-12-28 19:17:19');

