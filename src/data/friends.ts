// 友情链接数据配置
// 用于管理友情链接页面的数据

export interface FriendItem {
	id: number;
	title: string;
	imgurl: string;
	desc: string;
	siteurl: string;
	tags: string[];
}

// 友情链接数据
export const friendsData: FriendItem[] = [
	{
		id: 9,
		title: "lyrumu's page",
		imgurl: "/images/friends/lyrumu.webp",
		desc: "分享编程与工具实践，整理学习笔记、个人项目与日常记录。",
		siteurl: "https://lyrumu.top/",
		tags: ["博客"],
	},
	{
		id: 10,
		title: "炒米线",
		imgurl: "/images/friends/chaomixian.jpeg",
		desc: "米线、米线，你听我说！ - 我 Chao！",
		siteurl: "https://blog.chaomixian.top/",
		tags: ["博客"],
	},
	{
		id: 11,
		title: "Timmy's Blog",
		imgurl: "/images/friends/timmy.jpg",
		desc: "记录技术、生活与持续折腾",
		siteurl: "https://blog.timmy.host/",
		tags: ["博客"],
	},
	{
		id: 12,
		title: "C3ngH",
		imgurl: "/images/friends/c3ngh.jpg",
		desc: "允许一切如其所是",
		siteurl: "https://c3ngh.top/",
		tags: ["博客", "学长"],
	},
	{
		id: 13,
		title: "A1ic3's House",
		imgurl: "/images/friends/a1ic3.jpg",
		desc: "Every adventure requires a first setups",
		siteurl: "https://a1ic3.cn/",
		tags: ["博客", "学长"],
	},
	{
		id: 14,
		title: "温婳霂",
		imgurl: "/images/friends/somokel.webp",
		desc: "I MEET YOU HERE.",
		siteurl: "https://somokel.github.io/",
		tags: ["博客", "学长"],
	},
	{
		id: 15,
		title: "sanitietatuji",
		// 网站暂时返回 404，待确认地址后替换为网站头像。
		imgurl: "/images/friends/sanitietatuji.svg",
		desc: "学长的个人博客",
		siteurl: "https://sanitietatuji.github.io/",
		tags: ["博客", "学长"],
	},
];

// 获取所有友情链接数据
export function getFriendsList(): FriendItem[] {
	return friendsData;
}

// 获取随机排序的友情链接数据
export function getShuffledFriendsList(): FriendItem[] {
	const shuffled = [...friendsData];
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled;
}
